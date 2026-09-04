"""Cliente de referencia para la plataforma SaaS: invoca el ALB interno y maneja reintentos.

Política de reintentos (según el código de error del nodo):
  * 503/504 con retryable=true  -> reintentar (el ALB enviará a otro nodo); backoff corto.
  * 423 (pin_rejected/pin_locked) -> NO reintentar: alerta inmediata a operaciones.
  * 4xx restantes -> error del documento/petición: no reintentar.
"""
from __future__ import annotations

import base64
import time
import uuid

import httpx


class SignClient:
    def __init__(self, base_url: str, api_key: str, ca_bundle: str | bool = True, timeout: float = 45.0):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, verify=ca_bundle, timeout=timeout,
                                   headers={"X-Api-Key": api_key})

    def sign(self, pdf_bytes: bytes, document_id: str, *, reason: str | None = None,
             visible: dict | None = None, max_attempts: int = 4) -> dict:
        payload = {
            "document_id": document_id,
            "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
            "metadata": {"reason": reason, "visible": visible},
        }
        rid = uuid.uuid4().hex
        delay = 1.0
        for attempt in range(1, max_attempts + 1):
            r = self.client.post("/api/v1/sign-document", json=payload, headers={"X-Request-Id": rid})
            if r.status_code == 200:
                data = r.json()
                data["signed_pdf"] = base64.b64decode(data.pop("signed_pdf_base64"))
                return data
            err = (r.json().get("error") if r.headers.get("content-type", "").startswith("application/json") else None) or {}
            if r.status_code in (502, 503, 504) and err.get("retryable", True) and attempt < max_attempts:
                time.sleep(delay); delay = min(delay * 2, 8.0)
                continue
            raise RuntimeError(f"Firma fallida [{r.status_code}] {err.get('code')}: {err.get('message')} (nodo {err.get('node_id')}, req {rid})")
        raise RuntimeError("Firma fallida tras reintentos")


if __name__ == "__main__":
    import sys
    c = SignClient(sys.argv[1], sys.argv[2])
    res = c.sign(open(sys.argv[3], "rb").read(), document_id="POL-DEMO-1", reason="Emisión de póliza")
    open(sys.argv[4], "wb").write(res["signed_pdf"])
    print({k: v for k, v in res.items() if k != "signed_pdf"})
