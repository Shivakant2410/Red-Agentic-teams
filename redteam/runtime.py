"""Runtime autonomy controls: budgets, kill switch, transcript compaction, resume.

An unattended agent needs guardrails on *itself*, not just on its targets:
  - BudgetTracker enforces a wall-clock deadline, a total-LLM-token ceiling, and a kill
    switch (a file an operator can drop to stop a run cleanly).
  - compact_messages keeps the transcript bounded. The knowledge graph is the durable
    memory, so old tool chatter can be dropped without losing what was learned — the
    planner re-injects current state every turn anyway.
  - RunManifest persists run metadata so an interrupted engagement can resume (findings,
    graph, and audit log already persist to the run directory).
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .events import safe_emit


class Halt(Exception):
    """Raised to stop the agent loop cleanly (budget spent, deadline hit, or kill switch)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# Markers that indicate a tool call did not succeed. Used by the repetition guard to
# decide whether an identical retry is worth allowing.
_FAILURE_MARKERS = ("error", "blocked", "denied", "refused", "stop:",
                    '"ok": false', '"recorded": false', '"ok":false', '"recorded":false',
                    "failed", "not_reproducible", "rejected", "no stored session",
                    "out of scope", "unknown tool", "bad arguments")


def looks_failed(result: str) -> bool:
    """Heuristic: did a tool result represent a failure/no-op the agent shouldn't just retry?"""
    low = (result or "").strip().lower()
    return any(m in low[:400] for m in _FAILURE_MARKERS)


class RepetitionGuard:
    """Breaks the death-spiral where a weak model retries the same failing call forever.

    Tracks consecutive failures per (tool, args) signature. After `threshold` identical
    failures, the next duplicate is blocked with a corrective message telling the agent
    to pivot — which is exactly the cyclical-reasoning failure small models fall into
    (see the Structured Attack Tree paper). A success resets that signature's counter.
    """

    def __init__(self, threshold: int = 3):
        self._threshold = threshold
        self._fails: dict[str, int] = {}

    def check_before(self, signature: str) -> str | None:
        if self._fails.get(signature, 0) >= self._threshold:
            return (
                "BLOCKED-REPEAT: you have already made this exact call "
                f"{self._fails[signature]} times and it failed every time. Do NOT repeat "
                "it. Pivot: try a different endpoint, technique, or inputs. If login keeps "
                "failing and you have confirmed SQL injection there, authenticate using the "
                "injection payload itself (e.g. email \"' OR 1=1--\") instead of guessing "
                "credentials."
            )
        return None

    def record_result(self, signature: str, failed: bool) -> None:
        if failed:
            self._fails[signature] = self._fails.get(signature, 0) + 1
        else:
            self._fails[signature] = 0


class BudgetTracker:
    """Self-side budget for agentic loops: wall clock, tokens, tool calls, kill switch.

    The trip behavior is fail-closed (Halt, caught by the agent loop). The warn
    behavior is the W10 addition: at `warn_fraction` of any cap the tracker emits
    a 'budget.warn' event ONCE per scope, so the operator sees the loop burning
    budget BEFORE the halt — a trip without a warning is a dashboard surprise;
    a trip with one is telemetry. Every cap can be 0 = unlimited. Thread-safe:
    the exploit swarm runs specialist threads that call add_usage()/check()
    concurrently (see the lock comment below).
    """

    def __init__(self, max_seconds: int = 0, max_tokens: int = 0,
                 kill_file: Path | None = None, *, max_tool_calls: int = 0,
                 warn_fraction: float = 0.8, events=None):
        self._max_seconds = max_seconds
        self._max_tokens = max_tokens
        self._max_tool_calls = max_tool_calls
        self._warn_fraction = min(max(warn_fraction, 0.01), 1.0)
        self._events = events
        self._kill_file = Path(kill_file) if kill_file else None
        self._start = time.monotonic()
        self._tokens = 0
        self._tool_calls = 0
        self._warned: set[str] = set()   # scopes that already emitted budget.warn
        # A parallel exploit swarm (orchestrator.py) runs N specialist contexts in
        # concurrent threads, each calling add_usage()/check() after every LLM turn —
        # self._tokens += ... is a read-modify-write race without this lock, which would
        # silently under-count tokens (and so blow past the intended budget) under
        # concurrent use.
        self._lock = threading.Lock()

    def _maybe_warn(self, scope: str, used: float, cap: float) -> None:
        """Emit budget.warn once per scope at warn_fraction of the cap. Never raises."""
        if scope in self._warned or cap <= 0:
            return
        if used / cap >= self._warn_fraction:
            self._warned.add(scope)
            safe_emit(self._events, "budget.warn", scope=scope, used=used,
                      cap=cap, fraction=round(used / cap, 3))

    def _emit_exceeded(self, scope: str, used: float, cap: float) -> None:
        safe_emit(self._events, "budget.exceeded", scope=scope, used=used, cap=cap)

    def add_usage(self, usage: dict | None) -> None:
        if not usage:
            return
        total = usage.get("total_tokens")
        if total is None:
            total = (usage.get("prompt_tokens", 0) or 0) + (usage.get("completion_tokens", 0) or 0)
        with self._lock:
            self._tokens += int(total or 0)

    def count_tool_call(self, n: int = 1) -> None:
        """Record n dispatched tool calls; trip the cap (with a prior warning if owed).

        W10: the agentic loop's tool calls are the self-side cost driver no one
        capped — a swarm burning 500 browser_navigate calls against a slow target
        is a cost incident even when every request is polite.
        """
        with self._lock:
            self._tool_calls += max(n, 0)
            used = self._tool_calls
        self._maybe_warn("tool_calls", used, self._max_tool_calls)
        if self._max_tool_calls and used >= self._max_tool_calls:
            self._emit_exceeded("tool_calls", used, self._max_tool_calls)
            raise Halt(f"tool-call budget reached ({self._max_tool_calls})")

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def tokens(self) -> int:
        with self._lock:
            return self._tokens

    @property
    def tool_calls(self) -> int:
        with self._lock:
            return self._tool_calls

    def check(self) -> None:
        if self._kill_file and self._kill_file.exists():
            raise Halt(f"kill switch present ({self._kill_file.name})")
        elapsed = self.elapsed
        if self._max_seconds:
            self._maybe_warn("seconds", elapsed, self._max_seconds)
            if elapsed >= self._max_seconds:
                self._emit_exceeded("seconds", round(elapsed, 1), self._max_seconds)
                raise Halt(f"wall-clock budget reached ({self._max_seconds}s)")
        with self._lock:
            tokens = self._tokens
            tool_calls = self._tool_calls
        if self._max_tokens:
            self._maybe_warn("tokens", tokens, self._max_tokens)
            if tokens >= self._max_tokens:
                self._emit_exceeded("tokens", tokens, self._max_tokens)
                raise Halt(f"LLM token budget reached ({self._max_tokens})")
        if self._max_tool_calls:
            self._maybe_warn("tool_calls", tool_calls, self._max_tool_calls)
            if tool_calls >= self._max_tool_calls:
                self._emit_exceeded("tool_calls", tool_calls, self._max_tool_calls)
                raise Halt(f"tool-call budget reached ({self._max_tool_calls})")

    def status(self) -> dict:
        with self._lock:
            tokens = self._tokens
            tool_calls = self._tool_calls
        return {"elapsed_s": round(self.elapsed, 1), "tokens": tokens,
                "tool_calls": tool_calls, "max_seconds": self._max_seconds,
                "max_tokens": self._max_tokens,
                "max_tool_calls": self._max_tool_calls}


def compact_messages(messages: list[dict], keep_last: int = 16,
                     threshold: int = 30) -> list[dict]:
    """Bound the transcript. Keep the system prompt + initial objective + a compaction
    marker + the last `keep_last` messages. Drops leading orphan 'tool' messages in the
    tail so tool_call/tool pairs never break."""
    if len(messages) <= threshold:
        return messages
    head = messages[:2]  # system + objective
    tail = messages[-keep_last:]
    # A tool message must follow the assistant tool_calls that spawned it; if the tail
    # starts mid-pair, drop those orphans.
    while tail and tail[0].get("role") == "tool":
        tail = tail[1:]
    marker = {"role": "user",
              "content": "[earlier steps compacted — rely on the KNOWN STATE briefing below]"}
    return [*head, marker, *tail]


@dataclass
class RunManifest:
    objective: str
    engagement: str
    started: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    updated: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    status: str = "running"           # running | completed | halted | error
    steps: int = 0
    findings: int = 0
    tokens: int = 0
    halt_reason: str = ""

    def save(self, path: str | Path) -> None:
        self.updated = _dt.datetime.now(_dt.timezone.utc).isoformat()
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "RunManifest | None":
        p = Path(path)
        if not p.exists():
            return None
        return cls(**json.loads(p.read_text(encoding="utf-8")))
