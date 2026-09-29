"""Authenticated session store — the state that makes chained attacks possible.

IDOR and broken-access-control testing require acting *as* an authenticated principal:
log in once, hold the token/cookie, then replay requests with that identity. This store
keeps named sessions (e.g. "userA", "admin") so the chained-attack tools can compare
"as user A" vs "as user B" vs "no auth".
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Session:
    label: str
    headers: dict = field(default_factory=dict)   # e.g. {"Authorization": "Bearer ...", "Cookie": "..."}

    def apply(self, headers: dict | None = None) -> dict:
        """Merge this session's auth onto a request's headers (session wins)."""
        merged = dict(headers or {})
        merged.update(self.headers)
        return merged


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def set(self, label: str, headers: dict) -> Session:
        s = Session(label=label, headers=dict(headers))
        self._sessions[label] = s
        return s

    def get(self, label: str) -> Session | None:
        return self._sessions.get(label)

    def labels(self) -> list[str]:
        return list(self._sessions)
