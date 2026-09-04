"""Log de auditoría inmutable (append-only, encadenado por hash) + telemetría asíncrona.

Cada registro incluye el hash SHA-256 del registro anterior y su propio hash, de modo que
cualquier alteración o borrado intermedio rompe la cadena y es detectable (verificar con
`python -m app.audit verify <archivo>`). El archivo se abre en modo append (O_APPEND) y el
servicio corre con ProtectSystem=strict: solo puede escribir en su directorio de logs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import sys
import threading
from datetime import datetime, timezone

log = logging.getLogger("firma.audit")

GENESIS = "0" * 64


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class AuditLog:
    def __init__(self, path: str, node_id: str, telemetry_endpoint: str = ""):
        self.path = path
        self.node_id = node_id
        self._lock = threading.Lock()
        self._prev = self._last_hash()
        self._seq = self._last_seq()
        self._telemetry = None
        if telemetry_endpoint:
            self._telemetry = _Telemetry(telemetry_endpoint)

    # ------------------------------------------------------------ lectura
    def _tail(self) -> dict | None:
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return None
                f.seek(max(0, size - 65536))
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
                return json.loads(lines[-1]) if lines else None
        except FileNotFoundError:
            return None
        except Exception as e:  # noqa: BLE001
            log.error("No se pudo leer la cola del log de auditoría: %r", e)
            return None

    def _last_hash(self) -> str:
        t = self._tail()
        return t.get("hash", GENESIS) if t else GENESIS

    def _last_seq(self) -> int:
        t = self._tail()
        return int(t.get("seq", 0)) if t else 0

    # ------------------------------------------------------------ escritura
    def record(self, event: str, **fields) -> dict:
        with self._lock:
            self._seq += 1
            rec = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "node": self.node_id,
                "event": event,
                **fields,
                "prev_hash": self._prev,
            }
            rec["hash"] = hashlib.sha256(_canonical({k: v for k, v in rec.items() if k != "hash"})).hexdigest()
            line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                log.critical("FALLO DE AUDITORÍA: no se pudo persistir el registro %s: %r", self._seq, e)
            self._prev = rec["hash"]
        if self._telemetry:
            self._telemetry.push(rec)
        return rec


class _Telemetry:
    """Envío asíncrono y best-effort de registros al colector en AWS (a través del túnel)."""

    def __init__(self, endpoint: str, maxsize: int = 5000):
        self.endpoint = endpoint
        self.q: queue.Queue = queue.Queue(maxsize=maxsize)
        threading.Thread(target=self._worker, name="telemetry", daemon=True).start()

    def push(self, rec: dict) -> None:
        try:
            self.q.put_nowait(rec)
        except queue.Full:
            log.warning("Cola de telemetría llena; registro %s solo en disco", rec.get("seq"))

    def _worker(self) -> None:
        import httpx  # import tardío

        with httpx.Client(timeout=5.0) as client:
            while True:
                rec = self.q.get()
                try:
                    client.post(self.endpoint, json=rec)
                except Exception as e:  # noqa: BLE001
                    log.debug("Telemetría no entregada (seq=%s): %r", rec.get("seq"), e)


def verify(path: str) -> tuple[bool, str]:
    """Verifica la integridad de la cadena. Devuelve (ok, mensaje)."""
    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            rec = json.loads(ln)
            n += 1
            if rec.get("prev_hash") != prev:
                return False, f"Cadena rota en seq={rec.get('seq')} (prev_hash no coincide)"
            h = rec.pop("hash")
            if hashlib.sha256(_canonical(rec)).hexdigest() != h:
                return False, f"Hash inválido en seq={rec.get('seq')}"
            prev = h
    return True, f"{n} registros verificados; cadena íntegra"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        ok, msg = verify(sys.argv[2])
        print(msg)
        sys.exit(0 if ok else 1)
    print("uso: python -m app.audit verify <audit.jsonl>")
    sys.exit(2)
