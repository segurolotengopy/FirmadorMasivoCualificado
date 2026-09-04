"""Jerarquía de errores del dominio y su mapeo a códigos HTTP.

La distinción es operativa: el ALB y el centro de monitoreo en Bolivia deben poder saber,
sin leer logs, si el fallo es del documento (4xx, no reintentar), del hardware (503,
reintentar en otro nodo) o del PIN (423, intervención humana urgente: riesgo de bloqueo del token).
"""
from __future__ import annotations


class FirmaError(Exception):
    http_status = 500
    code = "internal_error"
    retryable = False

    def __init__(self, message: str = "", *, detail: str | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail


# --- Errores del cliente (no reintentar) ---
class InvalidPayload(FirmaError):
    http_status = 400
    code = "invalid_payload"


class InvalidPdf(FirmaError):
    http_status = 422
    code = "invalid_pdf"


class PayloadTooLarge(FirmaError):
    http_status = 413
    code = "payload_too_large"


class Unauthorized(FirmaError):
    http_status = 401
    code = "unauthorized"


# --- Errores de hardware / middleware (503: el ALB reenvía a otro nodo) ---
class TokenUnavailable(FirmaError):
    """El token no está presente o no es visible (extraído, puerto USB caído, udev sin symlink)."""
    http_status = 503
    code = "token_unavailable"
    retryable = True


class TokenRemovedDuringOperation(TokenUnavailable):
    """El hardware fue extraído a mitad de una firma (CKR_DEVICE_REMOVED)."""
    code = "token_removed_during_operation"


class SmartcardDaemonDown(FirmaError):
    """pcscd caído o socket inaccesible: el módulo PKCS#11 no puede enumerar slots."""
    http_status = 503
    code = "smartcard_daemon_down"
    retryable = True


class Pkcs11ModuleError(FirmaError):
    """El .so no existe, no carga o C_Initialize falló."""
    http_status = 503
    code = "pkcs11_module_error"
    retryable = True


class SigningTimeout(FirmaError):
    """El token no respondió dentro del tiempo máximo (posible cuelgue del lector)."""
    http_status = 504
    code = "signing_timeout"
    retryable = True


# --- Errores de credenciales (423: NO reintentar ciegamente; puede bloquear el token) ---
class PinRejected(FirmaError):
    http_status = 423
    code = "pin_rejected"


class PinLockedError(FirmaError):
    http_status = 423
    code = "pin_locked"


# --- Errores de certificado ---
class CertificateNotFound(FirmaError):
    http_status = 503
    code = "certificate_not_found"
    retryable = True


class CertificateExpired(FirmaError):
    http_status = 503
    code = "certificate_expired"


class TimestampError(FirmaError):
    """La TSA no respondió; la firma PAdES-B se completa pero sin sello (según política)."""
    http_status = 502
    code = "timestamp_authority_error"
    retryable = True
