"""Contratos de la API (request/response) del endpoint de firma."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class VisibleSignature(BaseModel):
    page: int = Field(0, ge=0, description="Página (índice 0) donde se dibuja la firma")
    box: tuple[int, int, int, int] = Field((400, 40, 580, 110), description="(x1, y1, x2, y2) en puntos PDF")


class SignMetadata(BaseModel):
    reason: str | None = Field(None, max_length=200)
    location: str | None = Field(None, max_length=200)
    contact: str | None = Field(None, max_length=200)
    field_name: str = Field("FirmaCualificada", pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    certify: bool = False
    with_timestamp: bool | None = Field(None, description="Forzar/omitir sello de tiempo; null = política del nodo")
    visible: VisibleSignature | None = None


class SignDocumentRequest(BaseModel):
    document_id: str = Field(..., min_length=1, max_length=128, description="Identificador de negocio (nro. de póliza, expediente)")
    pdf_base64: str = Field(..., min_length=20)
    metadata: SignMetadata = Field(default_factory=SignMetadata)

    @field_validator("pdf_base64")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class SignerInfo(BaseModel):
    subject: str
    issuer: str
    serial: str
    not_after: str


class SignDocumentResponse(BaseModel):
    status: Literal["signed"] = "signed"
    request_id: str
    document_id: str
    node_id: str
    signed_pdf_base64: str
    sha256_input: str
    sha256_output: str
    pades_level: str
    timestamped: bool
    field_name: str
    signer: SignerInfo
    signed_at: str
    duration_ms: int
    audit_seq: int
    audit_hash: str


class ErrorBody(BaseModel):
    code: str
    message: str
    retryable: bool
    request_id: str
    node_id: str


class ErrorResponse(BaseModel):
    error: ErrorBody
