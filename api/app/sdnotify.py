"""Cliente mínimo del protocolo sd_notify (sin dependencias) para Type=notify + WatchdogSec."""
from __future__ import annotations

import os
import socket


def notify(state: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(state.encode())
        return True
    except OSError:
        return False


def ready() -> bool:
    return notify("READY=1")


def watchdog_ping() -> bool:
    return notify("WATCHDOG=1")


def status(msg: str) -> bool:
    return notify(f"STATUS={msg[:200]}")


def watchdog_usec() -> int | None:
    """Intervalo de watchdog impuesto por systemd (WATCHDOG_USEC) o None si no aplica."""
    v = os.environ.get("WATCHDOG_USEC")
    return int(v) if v and v.isdigit() else None
