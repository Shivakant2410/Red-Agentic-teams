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
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


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
    def __init__(self, max_seconds: int = 0, max_tokens: int = 0, kill_file: Path | None = None):
        self._max_seconds = max_seconds
        self._max_tokens = max_tokens
        self._kill_file = Path(kill_file) if kill_file else None
        self._start = time.monotonic()
        self._tokens = 0

    def add_usage(self, usage: dict | None) -> None:
        if not usage:
            return
        total = usage.get("total_tokens")
        if total is None:
            total = (usage.get("prompt_tokens", 0) or 0) + (usage.get("completion_tokens", 0) or 0)
        self._tokens += int(total or 0)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    @property
    def tokens(self) -> int:
        return self._tokens

    def check(self) -> None:
        if self._kill_file and self._kill_file.exists():
            raise Halt(f"kill switch present ({self._kill_file.name})")
        if self._max_seconds and self.elapsed >= self._max_seconds:
            raise Halt(f"wall-clock budget reached ({self._max_seconds}s)")
        if self._max_tokens and self._tokens >= self._max_tokens:
            raise Halt(f"LLM token budget reached ({self._max_tokens})")

    def status(self) -> dict:
        return {"elapsed_s": round(self.elapsed, 1), "tokens": self._tokens,
                "max_seconds": self._max_seconds, "max_tokens": self._max_tokens}


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
