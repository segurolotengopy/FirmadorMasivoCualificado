"""Microservicio de Firma Cualificada F2 - aplicación FastAPI.

Endpoints:
  GET  /health                 -> 200 si el token y el certificado son utilizables; 503 en caso contrario
                                  (el ALB usa este código para incluir/retirar el nodo del pool).
  GET  /api/v1/token-info      -> estado detallado del token/certificado (requiere X-Api-Key).
  POST /api/v1/sign-document   -> firma PAdES de un PDF en Base64, todo en memoria (requiere X-Api-Key).

Modelo de concurrencia: un único worker de firma (ThreadPoolExecutor(max_workers=1)). El token es
un recurso serial; las peticiones concurrentes se encolan en orden, y el ALB distribuye entre los 3
nodos según carga (least_outstanding_requests).
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import __version__
from . import exceptions as ex
from .audit import AuditLog
from .config import Settings, settings
from .schemas import ErrorResponse, SignDocumentRequest, SignDocumentResponse, SignerInfo
from .signer import SignOptions, sign_pdf_bytes
from .token_gateway import TokenGateway

log = logging.getLogger("firma.api")


class RuntimeState:
    """Estado compartido del proceso (inyectado en app.state)."""

    def __init__(self, cfg: Settings):
        self.cfg = cfg
        self.gateway = TokenGateway(cfg)
        self.audit = AuditLog(cfg.audit_log, cfg.node_id, cfg.telemetry_endpoint)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="signer")
        self.poisoned: str | None = None      # motivo por el que el proceso debe reiniciarse
        self.started_at = time.time()
        self.signatures_ok = 0
        self.signatures_failed = 0
        self._health_cache: tuple[float, dict, int] | None = None

    def poison(self, reason: str) -> None:
        """Marca el proceso como irrecuperable: el bucle de watchdog deja de notificar a systemd,
        que lo matará y reiniciará (Restart=always). Es la salida limpia ante hilos bloqueados en C."""
        if not self.poisoned:
            log.critical("Proceso marcado para reinicio por watchdog: %s", reason)
            self.audit.record("process_poisoned", reason=reason)
            self.poisoned = reason


@asynccontextmanager
async def lifespan(app: FastAPI):
    st = RuntimeState(settings)
    app.state.rt = st
    st.audit.record("service_start", version=__version__, pkcs11_module=settings.pkcs11_module)
    # Apertura anticipada de la sesión (no bloquea el arranque si el token no está).
    try:
        await asyncio.get_running_loop().run_in_executor(st.executor, st.gateway.ensure_open)
    except ex.FirmaError as e:
        log.warning("Token no disponible al arrancar (%s): el nodo quedará fuera del pool hasta que aparezca", e.code)
        st.audit.record("token_unavailable_at_start", code=e.code, message=e.message)
    yield
    st.audit.record("service_stop")
    st.gateway.invalidate("shutdown")
    st.executor.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="Firma Cualificada F2 - Nodo transaccional",
    version=__version__,
    lifespan=lifespan,
    docs_url=None, redoc_url=None, openapi_url=None,   # sin superficie extra en producción
    responses={503: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)


# ----------------------------------------------------------------------------- seguridad
async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = settings.api_key
    if not expected:
        raise ex.Unauthorized("FIRMA_API_KEY no configurada en el nodo")
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise ex.Unauthorized("API key inválida")


# ----------------------------------------------------------------------------- errores
def _error_response(request: Request, err: ex.FirmaError, status: int | None = None) -> JSONResponse:
    rid = getattr(request.state, "request_id", "-")
    body = {"error": {"code": err.code, "message": err.message, "retryable": err.retryable,
                      "request_id": rid, "node_id": settings.node_id}}
    headers = {"X-Request-Id": rid, "X-Node-Id": settings.node_id}
    if err.retryable:
        headers["Retry-After"] = "2"
    return JSONResponse(status_code=status or err.http_status, content=body, headers=headers)


@app.exception_handler(ex.FirmaError)
async def firma_error_handler(request: Request, err: ex.FirmaError):
    level = logging.ERROR if err.http_status >= 500 else logging.WARNING
    log.log(level, "%s: %s%s", err.code, err.message, f" | {err.detail}" if err.detail else "")
    return _error_response(request, err)


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, err: Exception):
    log.exception("Error no controlado")
    return _error_response(request, ex.FirmaError("Error interno", detail=repr(err)))


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex
    t0 = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-Id"] = request.state.request_id
    response.headers["X-Node-Id"] = settings.node_id
    response.headers["Server-Timing"] = f"total;dur={(time.perf_counter() - t0) * 1000:.1f}"
    return response


# ----------------------------------------------------------------------------- salud
@app.get("/health")
async def health(request: Request):
    st: RuntimeState = request.app.state.rt
    now = time.monotonic()
    if st._health_cache and now - st._health_cache[0] < 3.0:
        _, body, code = st._health_cache
        return JSONResponse(body, status_code=code)

    body: dict = {
        "node_id": settings.node_id, "version": __version__,
        "uptime_sec": int(time.time() - st.started_at),
        "signatures": {"ok": st.signatures_ok, "failed": st.signatures_failed},
        "token_device_present": st.gateway.device_present(),
    }
    code = 200
    if st.poisoned:
        body["status"] = "restarting"; body["reason"] = st.poisoned; code = 503
    else:
        try:
            probe = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(st.executor, st.gateway.probe), timeout=8.0)
            body.update(probe)
            body["status"] = "ok"
            days = (probe.get("certificate") or {}).get("days_to_expiry")
            if days is not None and days <= 30:
                body["warning"] = f"certificado vence en {days} días"
        except asyncio.TimeoutError:
            body["status"] = "degraded"; body["error"] = "probe_timeout"; code = 503
            st.poison("health probe bloqueado > 8 s (lector/pcscd colgado)")
        except ex.FirmaError as e:
            body["status"] = "unavailable"; body["error"] = e.code; body["message"] = e.message; code = 503
    st._health_cache = (now, body, code)
    return JSONResponse(body, status_code=code)


@app.get("/api/v1/token-info", dependencies=[Depends(require_api_key)])
async def token_info(request: Request):
    st: RuntimeState = request.app.state.rt
    probe = await asyncio.get_running_loop().run_in_executor(st.executor, st.gateway.probe)
    return {"node_id": settings.node_id, "location": settings.node_location, **probe}


# ----------------------------------------------------------------------------- firma
@app.post("/api/v1/sign-document", response_model=SignDocumentResponse, dependencies=[Depends(require_api_key)])
async def sign_document(req: SignDocumentRequest, request: Request):
    st: RuntimeState = request.app.state.rt
    rid = request.state.request_id
    t0 = time.perf_counter()

    if st.poisoned:
        raise ex.SmartcardDaemonDown("Nodo en reinicio controlado", detail=st.poisoned)

    # --- Decodificación en memoria ---
    try:
        pdf_bytes = base64.b64decode(req.pdf_base64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ex.InvalidPayload("pdf_base64 no es Base64 válido") from e
    max_bytes = settings.max_pdf_mb * 1024 * 1024
    if len(pdf_bytes) > max_bytes:
        raise ex.PayloadTooLarge(f"El PDF supera el máximo de {settings.max_pdf_mb} MB")
    sha_in = hashlib.sha256(pdf_bytes).hexdigest()

    m = req.metadata
    opts = SignOptions(
        field_name=m.field_name, reason=m.reason, location=m.location, contact=m.contact,
        certify=m.certify, with_timestamp=m.with_timestamp,
        visible=m.visible is not None,
        page=m.visible.page if m.visible else 0,
        box=tuple(m.visible.box) if m.visible else (400, 40, 580, 110),
    )

    def _do_sign():
        return st.gateway.run_locked(lambda signer: sign_pdf_bytes(pdf_bytes, signer, settings, opts))

    # --- Firma serializada en el worker del token, con tiempo máximo ---
    try:
        result = await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(st.executor, _do_sign),
            timeout=settings.sign_timeout_sec,
        )
    except asyncio.TimeoutError:
        st.signatures_failed += 1
        st.poison(f"firma bloqueada > {settings.sign_timeout_sec}s (request {rid})")
        st.audit.record("sign_timeout", request_id=rid, document_id=req.document_id, sha256_input=sha_in)
        raise ex.SigningTimeout("El token no respondió a tiempo; el nodo se reiniciará automáticamente")
    except ex.FirmaError as e:
        st.signatures_failed += 1
        st.audit.record("sign_failed", request_id=rid, document_id=req.document_id, sha256_input=sha_in,
                        code=e.code, message=e.message, detail=e.detail)
        raise

    sha_out = hashlib.sha256(result.pdf).hexdigest()
    ci = st.gateway.cert_info
    duration_ms = int((time.perf_counter() - t0) * 1000)
    st.signatures_ok += 1
    rec = st.audit.record(
        "sign_ok", request_id=rid, document_id=req.document_id,
        sha256_input=sha_in, sha256_output=sha_out, pades_level=result.pades_level,
        timestamped=result.timestamped, cert_serial=ci.serial if ci else None,
        cert_subject=ci.subject if ci else None, field_name=result.field_name,
        size_in=len(pdf_bytes), size_out=len(result.pdf), duration_ms=duration_ms,
    )
    return SignDocumentResponse(
        request_id=rid, document_id=req.document_id, node_id=settings.node_id,
        signed_pdf_base64=base64.b64encode(result.pdf).decode("ascii"),
        sha256_input=sha_in, sha256_output=sha_out,
        pades_level=result.pades_level, timestamped=result.timestamped, field_name=result.field_name,
        signer=SignerInfo(subject=ci.subject, issuer=ci.issuer, serial=ci.serial, not_after=ci.not_after.isoformat())
        if ci else SignerInfo(subject="?", issuer="?", serial="?", not_after="?"),
        signed_at=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        duration_ms=duration_ms, audit_seq=rec["seq"], audit_hash=rec["hash"],
    )
