"""Pasarela hacia el token criptográfico (PKCS#11).

Responsabilidades:
  * Cargar el módulo PKCS#11 (opensc-pkcs11.so o driver propietario) de forma perezosa.
  * Localizar el token correcto (por etiqueta o primer token presente) y abrir UNA sesión
    autenticada con el PIN de usuario, reutilizada entre peticiones.
  * Seleccionar el certificado de firma: por etiqueta explícita o, en su defecto, el
    certificado con keyUsage nonRepudiation (contentCommitment) cuya clave privada exista en el
    token (emparejados por CKA_ID). Esto evita firmar con el certificado de autenticación cuando
    el token trae ambos, como es habitual en tokens de firma cualificada.
  * Serializar el acceso al hardware (un token = un canal criptográfico) con un lock.
  * Traducir los errores de bajo nivel (CKR_*) a errores del dominio y descartar la sesión
    cuando el hardware desaparece, para reabrirla limpiamente en la siguiente petición.

Nada de lo que pasa por aquí toca el disco: PDFs y firmas viven en memoria.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pkcs11
from asn1crypto import x509
from pkcs11 import Attribute, ObjectClass
from pkcs11 import exceptions as p11ex

from . import exceptions as ex
from .config import Settings

log = logging.getLogger("firma.token")


@dataclass
class TokenInfo:
    label: str
    manufacturer: str
    model: str
    serial: str
    slot_description: str


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    label: str
    key_id_hex: str

    @property
    def days_to_expiry(self) -> int:
        return (self.not_after - datetime.now(timezone.utc)).days


def _translate(err: BaseException) -> ex.FirmaError:
    """Mapea excepciones de python-pkcs11 / carga del módulo al dominio."""
    if isinstance(err, ex.FirmaError):
        return err
    if isinstance(err, (p11ex.DeviceRemoved,)):
        return ex.TokenRemovedDuringOperation("El token fue extraído durante la operación", detail=repr(err))
    if isinstance(err, (p11ex.TokenNotPresent, p11ex.NoSuchToken, p11ex.SlotIDInvalid, p11ex.TokenNotRecognised)):
        return ex.TokenUnavailable("Token no presente o no reconocido", detail=repr(err))
    if isinstance(err, p11ex.PinLocked):
        return ex.PinLockedError("PIN bloqueado: requiere desbloqueo con PUK por la certificadora", detail=repr(err))
    if isinstance(err, (p11ex.PinIncorrect, p11ex.PinInvalid, p11ex.PinLenRange, p11ex.PinExpired)):
        return ex.PinRejected("PIN rechazado por el token", detail=repr(err))
    if isinstance(err, (p11ex.SessionHandleInvalid, p11ex.SessionClosed, p11ex.DeviceError, p11ex.GeneralError)):
        # Típico cuando pcscd se reinició por debajo del módulo o el lector se colgó.
        return ex.SmartcardDaemonDown("Sesión PKCS#11 inválida (¿pcscd reiniciado / lector caído?)", detail=repr(err))
    if isinstance(err, p11ex.FunctionFailed):
        return ex.SmartcardDaemonDown("CKR_FUNCTION_FAILED: fallo de comunicación con el lector", detail=repr(err))
    if isinstance(err, p11ex.PKCS11Error):
        return ex.Pkcs11ModuleError(f"Error PKCS#11: {err.__class__.__name__}", detail=repr(err))
    if isinstance(err, OSError):
        return ex.Pkcs11ModuleError("No se pudo cargar el módulo PKCS#11", detail=repr(err))
    return ex.FirmaError("Error interno en la capa criptográfica", detail=repr(err))


class TokenGateway:
    def __init__(self, settings: Settings):
        self.s = settings
        self._lock = threading.RLock()
        self._lib: Any = None
        self._session: Any = None
        self._signer: Any = None
        self._token_info: TokenInfo | None = None
        self._cert_info: CertInfo | None = None
        self._opened_at: float | None = None
        self._generation = 0  # se incrementa en cada invalidación (métrica de reconexiones)

    # ------------------------------------------------------------------ estado
    @property
    def generation(self) -> int:
        return self._generation

    @property
    def token_info(self) -> TokenInfo | None:
        return self._token_info

    @property
    def cert_info(self) -> CertInfo | None:
        return self._cert_info

    def device_present(self) -> bool:
        """Presencia física según udev (symlink anclado por número de serie)."""
        dev = self.s.token_device
        return (not dev) or os.path.exists(dev)

    # --------------------------------------------------------------- ciclo vida
    def invalidate(self, reason: str = "") -> None:
        """Descarta la sesión actual (token extraído, pcscd reiniciado, SIGUSR1 de udev)."""
        with self._lock:
            if self._session is not None:
                log.warning("Invalidando sesión PKCS#11 (%s)", reason or "sin motivo")
                try:
                    self._session.close()
                except Exception:  # noqa: BLE001 - el handle ya puede ser inválido
                    pass
            self._session = None
            self._signer = None
            self._token_info = None
            self._cert_info = None
            self._opened_at = None
            self._generation += 1

    def _load_lib(self):
        if self._lib is None:
            if not os.path.exists(self.s.pkcs11_module):
                raise ex.Pkcs11ModuleError(f"Módulo PKCS#11 inexistente: {self.s.pkcs11_module}")
            try:
                self._lib = pkcs11.lib(self.s.pkcs11_module)
            except Exception as e:  # noqa: BLE001
                raise ex.Pkcs11ModuleError("Fallo al cargar/inicializar el módulo PKCS#11", detail=repr(e)) from e
        return self._lib

    def _find_token(self, lib):
        try:
            slots = lib.get_slots(token_present=True)
        except p11ex.PKCS11Error as e:
            raise _translate(e) from e
        if not slots:
            raise ex.TokenUnavailable("Ningún token presente en los slots PKCS#11")
        wanted = self.s.pkcs11_token_label.strip()
        for slot in slots:
            try:
                tok = slot.get_token()
            except p11ex.PKCS11Error:
                continue
            if not wanted or tok.label.strip() == wanted:
                return slot, tok
        raise ex.TokenUnavailable(f"No hay token con etiqueta '{wanted}' (presentes: {[s.get_token().label.strip() for s in slots]})")

    def _select_certificate(self, session) -> tuple[x509.Certificate, bytes, str]:
        """Devuelve (certificado, CKA_ID, label) del certificado de firma."""
        query: dict = {Attribute.CLASS: ObjectClass.CERTIFICATE}
        if self.s.pkcs11_cert_label:
            query[Attribute.LABEL] = self.s.pkcs11_cert_label
        candidates = []
        for obj in session.get_objects(query):
            try:
                cert = x509.Certificate.load(obj[Attribute.VALUE])
            except Exception:  # noqa: BLE001
                continue
            candidates.append((cert, obj[Attribute.ID], obj[Attribute.LABEL] or ""))
        if not candidates:
            raise ex.CertificateNotFound("El token no contiene certificados" + (f" con etiqueta '{self.s.pkcs11_cert_label}'" if self.s.pkcs11_cert_label else ""))

        # Solo certificados con clave privada en el token (por CKA_ID)
        key_ids = {k[Attribute.ID] for k in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})}
        with_key = [c for c in candidates if c[1] in key_ids] or candidates

        def score(c):
            cert = c[0]
            ku = cert.key_usage_value.native if cert.key_usage_value is not None else set()
            now = datetime.now(timezone.utc)
            valid = cert['tbs_certificate']['validity']['not_before'].native <= now <= cert['tbs_certificate']['validity']['not_after'].native
            return (
                'non_repudiation' in ku,   # FEC: contentCommitment
                valid,
                'digital_signature' in ku,
                cert['tbs_certificate']['validity']['not_after'].native,
            )

        best = max(with_key, key=score)
        return best

    def _open(self) -> None:
        lib = self._load_lib()
        slot, tok = self._find_token(lib)
        try:
            session = tok.open(rw=False, user_pin=self.s.pkcs11_pin or None)
        except p11ex.PKCS11Error as e:
            raise _translate(e) from e
        try:
            cert, key_id, label = self._select_certificate(session)
            from pyhanko.sign.pkcs11 import PKCS11Signer  # import tardío: acelera el arranque
            signer = PKCS11Signer(
                session,
                signing_cert=cert,
                key_id=key_id,
                key_label=self.s.pkcs11_key_label or None,
                bulk_fetch=False,
                embed_roots=True,
            )
            # Fuerza la resolución de la clave privada ahora, no en la primera firma.
            signer.ensure_objects_loaded()
        except p11ex.PKCS11Error as e:
            session.close()
            raise _translate(e) from e
        except ex.FirmaError:
            session.close()
            raise

        validity = cert['tbs_certificate']['validity']
        self._cert_info = CertInfo(
            subject=cert.subject.human_friendly,
            issuer=cert.issuer.human_friendly,
            serial=str(cert.serial_number),
            not_before=validity['not_before'].native,
            not_after=validity['not_after'].native,
            label=label,
            key_id_hex=(key_id or b"").hex(),
        )
        self._token_info = TokenInfo(
            label=tok.label.strip(), manufacturer=tok.manufacturer_id.strip(), model=tok.model.strip(),
            serial=tok.serial.strip(), slot_description=slot.slot_description.strip(),
        )
        self._session, self._signer, self._opened_at = session, signer, time.monotonic()
        log.info("Sesión PKCS#11 abierta: token=%s cert=%s vence=%s", self._token_info.label, self._cert_info.subject, self._cert_info.not_after.date())

    def ensure_open(self):
        """Devuelve el signer listo para usar, abriendo la sesión si es necesario."""
        with self._lock:
            if self._signer is None:
                if not self.device_present():
                    raise ex.TokenUnavailable(f"Token no detectado por udev ({self.s.token_device} ausente)")
                self._open()
            if self._cert_info and self._cert_info.not_after <= datetime.now(timezone.utc):
                raise ex.CertificateExpired(f"Certificado vencido el {self._cert_info.not_after.isoformat()}")
            return self._signer

    # ---------------------------------------------------------------- operación
    def run_locked(self, fn):
        """Ejecuta `fn(signer)` bajo el lock del hardware, traduciendo e invalidando ante fallos de dispositivo."""
        with self._lock:
            signer = self.ensure_open()
            try:
                return fn(signer)
            except p11ex.PKCS11Error as e:
                dom = _translate(e)
                if dom.retryable:
                    self.invalidate(f"{dom.code}: {e!r}")
                raise dom from e
            except ex.FirmaError:
                raise

    def probe(self) -> dict:
        """Health check profundo: intenta abrir/validar la sesión y leer los objetos del token."""
        with self._lock:
            self.ensure_open()
            try:
                # Operación ligera contra el hardware: enumerar la clave privada. Falla con
                # CKR_DEVICE_REMOVED / CKR_SESSION_HANDLE_INVALID si el token ya no está o pcscd se reinició.
                next(iter(self._session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY})), None)
            except p11ex.PKCS11Error as e:
                dom = _translate(e)
                self.invalidate(f"probe: {dom.code}")
                raise dom from e
            ci, ti = self._cert_info, self._token_info
            return {
                "token": ti.__dict__ if ti else None,
                "certificate": {
                    "subject": ci.subject, "issuer": ci.issuer, "serial": ci.serial,
                    "not_after": ci.not_after.isoformat(), "days_to_expiry": ci.days_to_expiry,
                    "label": ci.label, "key_id": ci.key_id_hex,
                } if ci else None,
                "session_age_sec": int(time.monotonic() - self._opened_at) if self._opened_at else None,
                "reconnections": self._generation,
            }
