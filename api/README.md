# firma-api — nodo transaccional

`python -m app` (systemd `Type=notify`). Configuración por variables `FIRMA_*` (ver `app/config.py`).

## Contrato

`POST /api/v1/sign-document` — cabecera `X-Api-Key`.
```json
{
  "document_id": "POL-2026-000123",
  "pdf_base64": "JVBERi0xLjc...",
  "metadata": {
    "reason": "Emisión de póliza", "location": "Asunción", "contact": "ops@...",
    "field_name": "FirmaCualificada", "certify": false, "with_timestamp": null,
    "visible": { "page": 0, "box": [350, 40, 560, 110] }
  }
}
```
Respuesta 200: `signed_pdf_base64`, `sha256_input/output`, `pades_level`, `signer{subject,issuer,serial,not_after}`, `audit_seq/hash`, `duration_ms`.

Errores (`{"error":{code,message,retryable,request_id,node_id}}`):

| HTTP | code | Causa | Acción del cliente |
|---|---|---|---|
| 400 | invalid_payload | Base64 inválido | corregir |
| 413 | payload_too_large | > FIRMA_MAX_PDF_MB | dividir |
| 422 | invalid_pdf | no es PDF / corrupto / cifrado | corregir |
| 401 | unauthorized | API key | revisar credenciales |
| 423 | pin_rejected / pin_locked | PIN incorrecto o token bloqueado | **no reintentar**; alerta |
| 503 | token_unavailable / token_removed_during_operation | token ausente o extraído | reintentar (otro nodo) |
| 503 | smartcard_daemon_down / pkcs11_module_error | pcscd caído / módulo .so | reintentar (otro nodo) |
| 503 | certificate_not_found / certificate_expired | token sin cert de firma / vencido | alerta |
| 504 | signing_timeout | token colgado; el nodo se autorreinicia | reintentar |
| 502 | timestamp_authority_error | TSA no responde | reintentar / política |

`GET /health` → 200 (token + certificado utilizables) / 503. `GET /api/v1/token-info` → detalle.

Señales: `SIGUSR1` invalida la sesión PKCS#11 (udev / selfcheck). `SIGTERM` apagado limpio.
