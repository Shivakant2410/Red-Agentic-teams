"""Model/backend pinning with drift alarms (W14).

Rug-pull is a demonstrated attack on agentic stacks: the Cursor tool-swap RCE
(CVE-2025-54135) replaced an APPROVED tool after the human clicked allow. The
same dynamic applies to model routing — a backend behind a qualified role can
change behavior after it was vetted, no exploit required, just a vendor deploy.
Pins are (key -> fingerprint) records made when a configuration is qualified;
check() recomputes the live configuration's fingerprints and diffs.

Drift policy: alarm, don't crash. A run mid-flight should degrade LOUDLY (a
'pin.drift' event on the EventBus, visible on the dashboard) rather than die —
the operator decides whether to continue. Strict mode (CI gates, pre-flight
checks) raises PinDriftError instead, which is the acceptance test the paper
names: "a backend swap trips a visible alarm."

Fail-closed on the registry itself: a corrupt pins file loads as an empty
registry flagged corrupt=True, and check() prepends a 'registry_corrupt' alarm —
drift detection that silently swallowed its own state loss would be exactly the
kind of quiet failure this module exists to prevent.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .events import safe_emit


class PinDriftError(RuntimeError):
    """Raised in strict mode when live configuration no longer matches its pins."""


@dataclass
class Pin:
    key: str
    fingerprint: str
    model: str = ""
    backend: str = ""
    pinned_at: str = ""

    def to_dict(self) -> dict:
        return {"key": self.key, "fingerprint": self.fingerprint,
                "model": self.model, "backend": self.backend,
                "pinned_at": self.pinned_at}


def fingerprint(payload) -> str:
    """Stable content fingerprint of a configuration payload (order-insensitive).

    16 hex chars — collision risk across a fleet of configs is negligible, and
    short fingerprints belong in dashboards and alarm lines where humans read them.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class PinRegistry:
    """(key -> Pin) store with drift checking, event alarms, and atomic persistence."""

    def __init__(self, pins: dict[str, Pin] | None = None, path: str | Path | None = None,
                 corrupt: bool = False):
        self._pins: dict[str, Pin] = dict(pins or {})
        self.path = Path(path) if path else None
        self.corrupt = corrupt

    # -- pinning ------------------------------------------------------------

    def pin(self, key: str, *, model: str = "", backend: str = "",
            config=None, at: str | None = None) -> Pin:
        """Pin `key` to the fingerprint of `config` (any JSON-able payload)."""
        rec = Pin(key=key, fingerprint=fingerprint(config if config is not None
                                                   else {"model": model, "backend": backend}),
                  model=model, backend=backend,
                  pinned_at=at or _dt.datetime.now(_dt.timezone.utc).isoformat())
        self._pins[key] = rec
        return rec

    def get(self, key: str) -> Pin | None:
        return self._pins.get(key)

    def __len__(self) -> int:
        return len(self._pins)

    def __contains__(self, key: str) -> bool:
        return key in self._pins

    # -- drift checking -----------------------------------------------------

    def check(self, live: dict[str, object]) -> list[dict]:
        """Diff the live configuration against the pins.

        `live` maps pin-key -> the same payload shape that was pinned. Alarms:
          - registry_corrupt: the pins file failed to load (fail-closed visibility)
          - unpinned: a live key with no pin — an UNPINNED dependency is itself drift
          - changed: fingerprint mismatch — the rug was pulled
        """
        alarms: list[dict] = []
        if self.corrupt:
            alarms.append({"key": "*", "kind": "registry_corrupt",
                           "detail": "pins file unreadable — enforcement is blind; "
                                     "re-pin before trusting 'no drift'"})
        for key in sorted(live):
            actual = fingerprint(live[key])
            pin = self._pins.get(key)
            if pin is None:
                alarms.append({"key": key, "kind": "unpinned", "actual": actual,
                               "detail": "no pin for this key — qualify and pin it"})
            elif pin.fingerprint != actual:
                alarms.append({"key": key, "kind": "changed",
                               "expected": pin.fingerprint, "actual": actual,
                               "detail": f"expected {pin.fingerprint}, live is {actual} — "
                                         "the thing behind this key moved after qualification"})
        return alarms

    def check_and_emit(self, live: dict[str, object], events=None,
                       strict: bool = False) -> list[dict]:
        """check() + one 'pin.drift' event per alarm; strict mode raises instead.

        Emission never raises (safe_emit) — alarms must reach the dashboard even
        when the bus is dead. strict=True is the CI/pre-flight contract.
        """
        alarms = self.check(live)
        for a in alarms:
            safe_emit(events, "pin.drift", key=a["key"], kind=a["kind"],
                      fingerprint=a.get("actual", ""), detail=a.get("detail", ""))
        if strict and alarms:
            summary = ", ".join(f"{a['key']}:{a['kind']}" for a in alarms)
            raise PinDriftError(f"pin drift detected ({summary})")
        return alarms

    # -- persistence ----------------------------------------------------------

    def save(self) -> None:
        """Atomic write (tmp + os.replace) — a crash mid-save must not corrupt pins."""
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "pins": {k: p.to_dict() for k, p in self._pins.items()}}
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | Path) -> "PinRegistry":
        """Load pins; a missing file is 'no pins yet', a CORRUPT file is flagged.

        Corruption is surfaced (registry.corrupt == True -> 'registry_corrupt'
        alarm on every check), never swallowed: pins enforcement that quietly
        lost its state would report 'no drift' while enforcing nothing.
        """
        p = Path(path)
        if not p.exists():
            return cls(pins={}, path=p, corrupt=False)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            pins = {k: Pin(**{**rest, "key": k}) for k, rest in
                    (data.get("pins") or {}).items()}
            return cls(pins=pins, path=p, corrupt=False)
        except (json.JSONDecodeError, OSError, TypeError):
            return cls(pins={}, path=p, corrupt=True)
