"""Firma PAdES en memoria con pyHanko.

Flujo: bytes del PDF -> IncrementalPdfFileWriter (BytesIO) -> PdfSigner + PKCS11Signer
-> BytesIO de salida. En ningún punto se escribe en disco; el PDF original se preserva
íntegro (firma incremental) y el resultado es un PAdES-B-B, -B-T (con TSA) o -B-LT
(con información de validación embebida), según configuración.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from io import BytesIO

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign.timestamps import TimestampRequestError

from . import exceptions as ex
from .config import Settings

log = logging.getLogger("firma.signer")


@dataclass
class SignOptions:
    field_name: str = "FirmaCualificada"
    reason: str | None = None
    location: str | None = None
    contact: str | None = None
    visible: bool = False
    page: int = 0                                   # índice 0-based
    box: tuple[int, int, int, int] = (400, 40, 580, 110)  # (x1, y1, x2, y2) en puntos PDF
    certify: bool = False                            # firma de certificación (bloquea cambios posteriores)
    with_timestamp: bool | None = None               # None = según configuración del nodo


@dataclass
class SignResult:
    pdf: bytes
    pades_level: str
    field_name: str
    timestamped: bool


def _pades_level(settings: Settings, timestamped: bool) -> str:
    if settings.embed_validation_info:
        return "PAdES-B-LT" if timestamped else "PAdES-B-B+VRI"
    return "PAdES-B-T" if timestamped else "PAdES-B-B"


def sign_pdf_bytes(pdf_bytes: bytes, signer, settings: Settings, opts: SignOptions) -> SignResult:
    # --- Parseo en memoria ---
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ex.InvalidPdf("El contenido no es un PDF (cabecera %PDF- ausente)")
    try:
        writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes), strict=False)
    except PdfReadError as e:
        raise ex.InvalidPdf(f"PDF ilegible o corrupto: {e}") from e
    except Exception as e:  # noqa: BLE001
        raise ex.InvalidPdf("PDF no procesable", detail=repr(e)) from e

    if writer.prev.encrypted:
        raise ex.InvalidPdf("El PDF está cifrado; debe entregarse sin cifrar para firmarlo")

    # --- Sello de tiempo (PAdES-T) ---
    want_ts = settings.tsa_url and (opts.with_timestamp is not False)
    timestamper = HTTPTimeStamper(settings.tsa_url, timeout=10) if want_ts else None

    # --- Metadatos de la firma ---
    validation_context = None
    if settings.embed_validation_info:
        from pyhanko_certvalidator import ValidationContext
        validation_context = ValidationContext(allow_fetching=True)

    meta = signers.PdfSignatureMetadata(
        field_name=opts.field_name,
        md_algorithm=settings.md_algorithm,
        subfilter=SigSeedSubFilter.PADES,
        reason=opts.reason or settings.sig_reason or None,
        location=opts.location or settings.sig_location or None,
        contact_info=opts.contact or settings.sig_contact or None,
        certify=opts.certify,
        docmdp_permissions=fields.MDPPerm.NO_CHANGES if opts.certify else fields.MDPPerm.FILL_FORMS,
        embed_validation_info=bool(settings.embed_validation_info),
        validation_context=validation_context,
        use_pades_lta=False,
    )

    new_field_spec = None
    if opts.visible:
        new_field_spec = SigFieldSpec(sig_field_name=opts.field_name, on_page=opts.page, box=opts.box)

    pdf_signer = signers.PdfSigner(meta, signer=signer, timestamper=timestamper, new_field_spec=new_field_spec)

    # --- Firma ---
    out = BytesIO()
    try:
        pdf_signer.sign_pdf(writer, output=out, in_place=False)
    except TimestampRequestError as e:
        raise ex.TimestampError(f"La TSA {settings.tsa_url} no emitió el sello de tiempo", detail=repr(e)) from e
    except ex.FirmaError:
        raise
    # Las excepciones PKCS#11 (token extraído, pcscd caído) atraviesan hasta TokenGateway.run_locked,
    # que las traduce e invalida la sesión.

    return SignResult(
        pdf=out.getvalue(),
        pades_level=_pades_level(settings, bool(timestamper)),
        field_name=opts.field_name,
        timestamped=bool(timestamper),
    )
