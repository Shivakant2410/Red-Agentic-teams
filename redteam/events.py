"""EventBus — run telemetry for humans watching.

Gen-1 was opaque: unless you tail-watched files appear in the run directory, you had no
idea what the agents were doing. The dashboard (and the headless API) need a live,
ordered, replayable stream of what every specialist is thinking and doing — so the
engine now emits typed events at every meaningful point (agent turns, tool calls,
findings, phase changes, approvals, reflections), and this bus fans them out to:

  - a JSONL file sink (events.jsonl in the run dir) — the source of truth; the API
    server serves both replay and live-tail from it, which keeps the server decoupled
    from the engine's process/thread topology (a run can even be a subprocess later);
  - in-process subscribers (callbacks) — used by tests and anything embedding the engine;
  - replay(): late joiners backfill from the file without missing a beat.

An event is a flat JSON dict: {seq, ts, run_id, type, **payload}. seq is a per-run
monotonic counter (the cursor every consumer tracks). Emission is thread-safe — the
exploit swarm emits from several specialist threads concurrently.

Design rule: emitting must NEVER break a run. emit() swallows sink failures (logged to
the audit log only), so a full disk or a dead subscriber can't kill an engagement.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
from pathlib import Path
from typing import Callable


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class FileSink:
    """Append-only JSONL writer; flush on every event so a tailing reader sees it now."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a", encoding="utf-8")

    def __call__(self, event: dict) -> None:
        self._fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()

    @property
    def path(self) -> Path:
        return self._path

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


def read_events(path: str | Path, after: int = 0, limit: int = 1000) -> list[dict]:
    """Replay events from a JSONL sink file with seq > after (the API's cursor contract).
    Tolerant of a torn last line (a writer mid-flush): that line is skipped, the next
    read picks up after it."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict) and ev.get("seq", 0) > after:
                out.append(ev)
                if len(out) >= limit:
                    break
    return out


class EventBus:
    def __init__(self, run_id: str, sink_path: str | Path | None = None,
                 subscribers: list[Callable[[dict], None]] | None = None):
        self.run_id = run_id
        self._seq = 0
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[dict], None]] = list(subscribers or [])
        self._file_sink: FileSink | None = FileSink(sink_path) if sink_path else None

    @property
    def cursor(self) -> int:
        with self._lock:
            return self._seq

    @property
    def sink_path(self) -> Path | None:
        """Where this bus persists events (None = memory-only). read_events() takes it."""
        fs = self._file_sink
        return fs.path if fs is not None else None

    def subscribe(self, fn: Callable[[dict], None]) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def emit(self, type: str, **fields) -> dict:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "ts": _now(), "run_id": self.run_id,
                     "type": type, **fields}
            subs = list(self._subscribers)
        # Fan-out outside the lock: a slow subscriber must not serialize emitters.
        # Sink first (ordering source of truth), then callbacks.
        for target in ([self._file_sink] if self._file_sink else []) + subs:
            try:
                target(event)
            except Exception:
                # Observability must never take the engagement down with it.
                pass
        return event

    def close(self) -> None:
        if self._file_sink is not None:
            self._file_sink.close()
            self._file_sink = None


def safe_emit(bus: "EventBus | None", type: str, **fields) -> None:
    """Emit to the bus if one exists; never raise. Use from tool code where the bus
    is optional (ctx.events may be None in legacy CLI runs)."""
    if bus is None:
        return
    try:
        bus.emit(type, **fields)
    except Exception:
        pass


def coerce_payload(value: object, limit: int = 300) -> str:
    """Compact any tool argument/result into a bounded preview string for events."""
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"
