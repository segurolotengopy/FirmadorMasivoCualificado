"""Punto de entrada (`python -m app`): servidor uvicorn embebido + integración systemd.

  * Type=notify: envía READY=1 cuando el servidor está escuchando.
  * WatchdogSec: envía WATCHDOG=1 cada WATCHDOG_USEC/3 mientras el proceso esté sano; si se marca
    como 'poisoned' (hilo de firma bloqueado en el driver) deja de hacerlo y systemd lo reinicia.
  * SIGUSR1 (enviado por udev al conectar/extraer el token o por firma-selfcheck): invalida la
    sesión PKCS#11 sin reiniciar el proceso; la siguiente petición reabre sesión.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

import uvicorn

from . import sdnotify
from .config import settings
from .main import app

LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


async def _watchdog_loop(interval: float) -> None:
    while True:
        rt = getattr(app.state, "rt", None)
        if rt is not None and rt.poisoned:
            sdnotify.status(f"POISONED: {rt.poisoned}")
            logging.getLogger("firma.watchdog").critical("Watchdog detenido: %s", rt.poisoned)
            return  # systemd matará el proceso al vencer WatchdogSec
        sdnotify.watchdog_ping()
        await asyncio.sleep(interval)


async def _serve() -> None:
    loop = asyncio.get_running_loop()

    def on_sigusr1() -> None:
        rt = getattr(app.state, "rt", None)
        if rt is not None:
            rt.gateway.invalidate("SIGUSR1 (evento de hardware)")
            rt._health_cache = None
            rt.audit.record("session_invalidated", reason="SIGUSR1")

    loop.add_signal_handler(signal.SIGUSR1, on_sigusr1)

    tls = bool(settings.tls_cert and settings.tls_key)
    config = uvicorn.Config(
        app,
        host=settings.bind_host,
        port=settings.bind_port,
        workers=1,
        loop="asyncio",
        log_level=settings.log_level.lower(),
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips="*",   # el ALB es el único cliente (red overlay)
        ssl_certfile=settings.tls_cert if tls else None,
        ssl_keyfile=settings.tls_key if tls else None,
        timeout_keep_alive=75,     # > idle_timeout del ALB (60 s) para evitar 502 por cierre anticipado
        limit_concurrency=64,
        server_header=False,
        date_header=True,
    )
    server = uvicorn.Server(config)

    # Watchdog: intervalo = WATCHDOG_USEC/3 (o FIRMA_WATCHDOG_SEC/3 fuera de systemd).
    usec = sdnotify.watchdog_usec()
    interval = (usec / 1_000_000 / 3) if usec else max(1.0, settings.watchdog_sec / 3)
    wd_task = asyncio.create_task(_watchdog_loop(interval))

    async def notify_ready_when_started() -> None:
        while not server.started:
            await asyncio.sleep(0.1)
        sdnotify.ready()
        sdnotify.status(f"escuchando en {settings.bind_host}:{settings.bind_port}")

    asyncio.create_task(notify_ready_when_started())
    try:
        await server.serve()
    finally:
        wd_task.cancel()


def main() -> int:
    logging.basicConfig(level=settings.log_level.upper(), format=LOG_FORMAT, stream=sys.stdout)
    logging.getLogger("firma").info(
        "Iniciando nodo %s (%s) tls=%s pkcs11=%s",
        settings.node_id, settings.node_location, bool(settings.tls_cert), settings.pkcs11_module,
    )
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
