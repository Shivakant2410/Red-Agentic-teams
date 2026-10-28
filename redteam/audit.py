"""Append-only, hash-chained audit log.

Every tool invocation — allowed or blocked — is written here as one JSON line. Each entry
carries the hash of the previous entry, forming a chain: altering or deleting any past
line breaks every hash after it, so the record you hand a client is tamper-evident. This
is the proof of exactly what the system did, when, and against which target.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._resume_chain()

    def _resume_chain(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, _GENESIS
        last = None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        if not last:
            return 0, _GENESIS
        try:
            row = json.loads(last)
            return int(row.get("seq", 0)) + 1, row.get("hash", _GENESIS)
        except (json.JSONDecodeError, ValueError):
            return 0, _GENESIS

    @staticmethod
    def _hash(prev_hash: str, payload: str) -> str:
        return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()

    def record(self, event: str, **fields: Any) -> None:
        with self._lock:
            entry = {
                "seq": self._seq,
                "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "event": event,
                "prev_hash": self._last_hash,
                **fields,
            }
            payload = json.dumps(entry, default=str, ensure_ascii=False, sort_keys=True)
            entry["hash"] = self._hash(self._last_hash, payload)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str, ensure_ascii=False) + "\n")
            self._last_hash = entry["hash"]
            self._seq += 1

    def read_all(self) -> list[dict]:
        if not self._path.exists():
            return []
        out = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def verify_chain(self) -> bool:
        """Return True if the hash chain is intact (nothing altered or removed)."""
        prev = _GENESIS
        for row in self.read_all():
            stored = row.get("hash")
            recomputed_input = {k: v for k, v in row.items() if k != "hash"}
            recomputed_input["prev_hash"] = prev
            payload = json.dumps(recomputed_input, default=str, ensure_ascii=False, sort_keys=True)
            if self._hash(prev, payload) != stored:
                return False
            prev = stored
        return True
