"""Pruebas sin hardware: firmante software (certificado autofirmado en memoria) inyectado en
TokenGateway, para validar la tubería PAdES, el contrato HTTP y el mapeo de errores PKCS#11.
Ejecutar: cd api && FIRMA_API_KEY=test FIRMA_AUDIT_LOG=/tmp/audit-test.jsonl python -m pytest -q
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from io import BytesIO

os.environ.setdefault("FIRMA_API_KEY", "test-key")
os.environ.setdefault("FIRMA_AUDIT_LOG", "/tmp/firma-audit-test.jsonl")
os.environ.setdefault("FIRMA_TOKEN_DEVICE", "")  # sin udev en pruebas

import pytest
from fastapi.testclient import TestClient
from pkcs11 import exceptions as p11ex

from app import exceptions as ex
from app.audit import verify
from app.main import app
from app.token_gateway import CertInfo, TokenGateway, _translate

HEADERS = {"X-Api-Key": "test-key"}


# ----------------------------------------------------------------------------- fixtures
def _software_signer():
    """SimpleSigner de pyHanko con un certificado autofirmado generado al vuelo."""
    from asn1crypto import x509 as ax509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore
    from pyhanko.keys import load_private_key_from_pemder_data

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prueba Firma F2"), x509.NameAttribute(NameOID.COUNTRY_NAME, "PY")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    a_cert = ax509.Certificate.load(cert_der)
    signer = signers.SimpleSigner(
        signing_cert=a_cert,
        signing_key=load_private_key_from_pemder_data(key_pem, passphrase=None),
        cert_registry=SimpleCertificateStore(),
    )
    info = CertInfo(subject=a_cert.subject.human_friendly, issuer=a_cert.issuer.human_friendly,
                    serial=str(a_cert.serial_number), not_before=now - timedelta(days=1),
                    not_after=now + timedelta(days=365), label="test", key_id_hex="01")
    return signer, info


def _minimal_pdf() -> bytes:
    from pyhanko.pdf_utils.writer import PdfFileWriter
    from pyhanko.pdf_utils import generic
    w = PdfFileWriter()
    page = generic.DictionaryObject({
        generic.pdf_name('/Type'): generic.pdf_name('/Page'),
        generic.pdf_name('/MediaBox'): generic.ArrayObject([generic.NumberObject(0), generic.NumberObject(0), generic.NumberObject(595), generic.NumberObject(842)]),
    })
    w.insert_page(page)
    out = BytesIO(); w.write(out); return out.getvalue()


@pytest.fixture(scope="module")
def client():
    signer, info = _software_signer()

    def fake_ensure_open(self):
        self._signer = signer; self._cert_info = info
        return signer

    def fake_probe(self):
        self.ensure_open()
        return {"token": {"label": "FAKE"}, "certificate": {"subject": info.subject, "days_to_expiry": 365}, "reconnections": 0}

    TokenGateway.ensure_open = fake_ensure_open
    TokenGateway.probe = fake_probe
    with TestClient(app) as c:
        yield c


# ----------------------------------------------------------------------------- pruebas HTTP
def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"


def test_sign_requires_api_key(client):
    r = client.post("/api/v1/sign-document", json={"document_id": "x", "pdf_base64": "QUJDREVGR0hJSktMTU5PUA=="})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_sign_document_pades_in_memory(client):
    pdf = _minimal_pdf()
    body = {"document_id": "POL-2026-000123", "pdf_base64": base64.b64encode(pdf).decode(),
            "metadata": {"reason": "Emisión de póliza", "visible": {"page": 0, "box": [350, 40, 560, 110]}}}
    r = client.post("/api/v1/sign-document", json=body, headers=HEADERS)
    assert r.status_code == 200, r.text
    data = r.json()
    signed = base64.b64decode(data["signed_pdf_base64"])
    assert signed.startswith(b"%PDF-") and len(signed) > len(pdf)
    assert data["pades_level"] == "PAdES-B-B" and data["timestamped"] is False
    assert data["field_name"] == "FirmaCualificada"
    assert data["sha256_output"] != data["sha256_input"]

    # Validación estructural de la firma con pyHanko
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    rd = PdfFileReader(BytesIO(signed))
    sig = rd.embedded_signatures[0]
    status = validate_pdf_signature(sig, ValidationContext(trust_roots=[sig.signer_cert], allow_fetching=False))
    assert status.intact and status.valid
    assert sig.field_name == "FirmaCualificada"

    # Cadena de auditoría íntegra
    ok, msg = verify(os.environ["FIRMA_AUDIT_LOG"])
    assert ok, msg


def test_invalid_base64(client):
    r = client.post("/api/v1/sign-document", json={"document_id": "x", "pdf_base64": "@@@no-base64@@@!!!!!!!"}, headers=HEADERS)
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_payload"


def test_not_a_pdf(client):
    r = client.post("/api/v1/sign-document", json={"document_id": "x", "pdf_base64": base64.b64encode(b"hola mundo esto no es pdf").decode()}, headers=HEADERS)
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_pdf"


# ----------------------------------------------------------------------------- mapeo PKCS#11
@pytest.mark.parametrize("p11, dom, status", [
    (p11ex.DeviceRemoved, ex.TokenRemovedDuringOperation, 503),
    (p11ex.TokenNotPresent, ex.TokenUnavailable, 503),
    (p11ex.SessionHandleInvalid, ex.SmartcardDaemonDown, 503),
    (p11ex.FunctionFailed, ex.SmartcardDaemonDown, 503),
    (p11ex.PinIncorrect, ex.PinRejected, 423),
    (p11ex.PinLocked, ex.PinLockedError, 423),
    (p11ex.MechanismInvalid, ex.Pkcs11ModuleError, 503),
])
def test_translate(p11, dom, status):
    d = _translate(p11())
    assert isinstance(d, dom) and d.http_status == status


def test_run_locked_invalidates_on_device_removed():
    from app.config import Settings
    gw = TokenGateway(Settings(token_device=""))
    gw._signer = object(); gw._session = None
    gw.ensure_open = lambda: gw._signer  # type: ignore[assignment]

    def boom(_):
        raise p11ex.DeviceRemoved()

    with pytest.raises(ex.TokenRemovedDuringOperation):
        gw.run_locked(boom)
    assert gw._signer is None and gw.generation == 1
