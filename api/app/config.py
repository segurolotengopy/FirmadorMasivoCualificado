"""Configuración del nodo, cargada desde el EnvironmentFile de systemd (prefijo FIRMA_)."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FIRMA_", extra="ignore")

    # Identidad del nodo
    node_id: str = "node-local"
    node_location: str = ""

    # Red
    bind_host: str = "127.0.0.1"
    bind_port: int = 8443
    tls_cert: str = ""
    tls_key: str = ""

    # Seguridad de la API
    api_key: str = Field(default="", description="Valor exigido en la cabecera X-Api-Key")
    max_pdf_mb: int = 25

    # PKCS#11
    pkcs11_module: str = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    pkcs11_token_label: str = ""
    pkcs11_cert_label: str = ""
    pkcs11_key_label: str = ""
    pkcs11_pin: str = ""
    token_device: str = "/dev/token-f2"   # symlink creado por la regla udev

    # Firma
    sig_reason: str = "Emisión de póliza electrónica"
    sig_location: str = "Asunción, Paraguay"
    sig_contact: str = ""
    tsa_url: str = ""
    embed_validation_info: bool = False
    md_algorithm: str = "sha256"

    # Operación
    audit_log: str = "/var/log/firma-api/audit.jsonl"
    telemetry_endpoint: str = ""
    watchdog_sec: int = 30
    log_level: str = "INFO"
    sign_timeout_sec: int = 40   # tiempo máximo de una operación de firma (token colgado)


settings = Settings()
