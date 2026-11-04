"""LLM targets — the thing under attack.

Ported shapes from the teardown of PyRIT's Targets and Lakera Red's "Targets /
Scans / Results" architecture (docs/competitor-landscape.md):

  - OpenAIChatTarget  — any /chat/completions endpoint (OpenAI, OpenRouter, Z.ai,
                        Ollama, vLLM, an internal gateway...). Stateless: every
                        send carries the full conversation.
  - SessionTarget     — the same wire format, but stateful: the campaign gets a
                        session id (sent via a configurable header) so multi-turn
                        and cross-session probes exercise the server's own
                        conversation state. Lakera's stateful-target pattern.
  - ScriptedTarget    — an in-process target with deterministic behavior. It
                        exists so the harness can be validated offline and so the
                        test suite never touches a network.

Fail-closed rules (this module's substitute for the sandbox firewall, which does
not help against an HTTPS chat endpoint):

  1. A target config without `authorized_by` AND `ticket` raises TargetAuthError
     at construction — no campaign may start against an unattributed target.
  2. Network targets must name `allowed_hosts` (exact hostnames, lowercase).
     Every HTTP call re-checks the URL host against the list BEFORE the request;
     a miss raises TargetAuthError. DNS aliases are not honored — list every host
     you mean to touch, the way `scope.allowed_hosts` works for the firewall.
  3. The API key is read from the environment by name, never logged, never put
     into attempt records (records carry hashes, not credentials).
"""

from __future__ import annotations

import base64 as _b64
import datetime as _dt
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import requests


class TargetError(Exception):
    """An HTTP-level failure from the target endpoint (status >= 400)."""


class TargetRateLimited(TargetError):
    """HTTP 429 from the target. Carries the Retry-After hint when present."""

    def __init__(self, retry_after: float | None = None):
        super().__init__(f"target rate-limited (retry_after={retry_after})")
        self.retry_after = retry_after


class TargetAuthError(ValueError):
    """The target config is unauthorized or tries to reach a host outside the
    explicit allowlist. Raised before any bytes leave the process."""


@dataclass(frozen=True)
class TargetConfig:
    """One LLM endpoint under test. Built from YAML/JSON via `from_mapping`."""

    name: str
    kind: str                      # openai_chat | session | scripted
    authorized_by: str
    ticket: str                    # reference into the signed authorization
    base_url: str = ""
    model: str = ""
    api_key_env: str = ""
    allowed_hosts: tuple[str, ...] = ()
    session_header: str = "X-Session-Id"
    extra_headers: dict = field(default_factory=dict)
    timeout: float = 60.0
    # Owner-known substrings of the system prompt (self-probing / B-lens use:
    # when WE red-team our own stack we KNOW what the hidden context says, so a
    # reply containing one of these is deterministic leak evidence).
    echo_markers: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, cfg: dict) -> "TargetConfig":
        if not isinstance(cfg, dict):
            raise TargetAuthError("target config must be a mapping")
        kind = str(cfg.get("kind", "openai_chat")).strip().lower()
        name = str(cfg.get("name", "")).strip()
        authorized_by = str(cfg.get("authorized_by", "")).strip()
        ticket = str(cfg.get("ticket", "")).strip()
        # Fail-closed rule 1: attribution is not optional, even for scripted
        # targets — the discipline is the point.
        if not name:
            raise TargetAuthError("target config is missing 'name'")
        if not authorized_by or not ticket:
            raise TargetAuthError(
                f"target {name!r} is missing 'authorized_by'/'ticket' — llmred "
                "refuses to run against an unattributed endpoint")
        base_url = str(cfg.get("base_url", "")).strip()
        hosts = tuple(
            str(h).strip().lower()
            for h in (cfg.get("allowed_hosts") or ()) if str(h).strip())
        if kind in {"openai_chat", "session"}:
            if not base_url.startswith(("http://", "https://")):
                raise TargetAuthError(
                    f"target {name!r}: network kinds require an http(s) base_url")
            if not str(cfg.get("model", "")).strip():
                raise TargetAuthError(f"target {name!r}: 'model' is required")
            # Fail-closed rule 2: no allowlist, no network target.
            if not hosts:
                raise TargetAuthError(
                    f"target {name!r}: network targets require a non-empty "
                    "'allowed_hosts' list")
        return cls(
            name=name,
            kind=kind,
            authorized_by=authorized_by,
            ticket=ticket,
            base_url=base_url,
            model=str(cfg.get("model", "")).strip(),
            api_key_env=str(cfg.get("api_key_env", "")).strip(),
            allowed_hosts=hosts,
            session_header=str(cfg.get("session_header", "X-Session-Id")),
            extra_headers=dict(cfg.get("extra_headers") or {}),
            timeout=float(cfg.get("timeout", 60.0)),
            echo_markers=tuple(str(m) for m in (cfg.get("echo_markers") or ())),
        )

    @property
    def fingerprint(self) -> str:
        """Stable identity of the endpoint for regression tracking (the thing
        that must stay constant between two compared releases). A hash of the
        identity triple — stable across processes, sensitive to every field."""
        import hashlib
        payload = json.dumps(
            {"kind": self.kind, "base_url": self.base_url, "model": self.model},
            sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:24]


@dataclass
class TargetReply:
    text: str
    status: int
    latency_ms: int
    session_id: str = ""


class LLMTarget(Protocol):
    """The campaign talks to exactly this surface — nothing else about an
    endpoint is needed, which keeps targets swappable with PyRIT's
    "everything is a target" looseness without its lock-in."""

    stateful: bool
    config: TargetConfig

    def new_session(self) -> str: ...
    def send(self, session: str, messages: list[dict]) -> TargetReply: ...


def assert_host_allowed(base_url: str, allowed_hosts: tuple[str, ...]) -> str:
    """Return the URL host if allowed; raise TargetAuthError otherwise.
    Called before EVERY outbound request — a target config that was valid at
    load time does not excuse a rewritten URL at call time."""
    host = (urlsplit(base_url).hostname or "").lower()
    if not host:
        raise TargetAuthError(f"URL {base_url!r} has no host")
    if host not in allowed_hosts:
        raise TargetAuthError(
            f"host {host!r} is not in the target's allowed_hosts {sorted(allowed_hosts)}")
    return host


def _post_chat(config: TargetConfig, url: str, headers: dict, payload: dict) -> requests.Response:
    """The single outbound HTTP chokepoint of the module (mirrors the role
    tools/http.py plays for the web side). Host allowlist is re-checked here so
    no caller can bypass it by building its own URL."""
    assert_host_allowed(url, config.allowed_hosts)
    headers = dict(headers)
    if config.api_key_env:
        key = __import__("os").environ.get(config.api_key_env, "")
        if key:
            headers.setdefault("Authorization", f"Bearer {key}")
    return requests.post(url, headers=headers, json=payload, timeout=config.timeout)


def _to_reply(resp: requests.Response, session: str) -> TargetReply:
    if resp.status_code == 429:
        retry = resp.headers.get("Retry-After")
        try:
            raise TargetRateLimited(float(retry) if retry else None)
        except (TypeError, ValueError):
            raise TargetRateLimited(None) from None
    if resp.status_code >= 400:
        raise TargetError(f"HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        body = resp.json()
        text = body["choices"][0]["message"]["content"] or ""
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"unrecognized response body: {exc}") from exc
    return TargetReply(text=text, status=resp.status_code,
                       latency_ms=int(resp.elapsed.total_seconds() * 1000),
                       session_id=session)


class OpenAIChatTarget:
    """Stateless OpenAI-compatible endpoint. Every send replays the full
    conversation (PyRIT's editable-history default), so state lives client-side
    and the server cannot blame session handling for a leak."""

    stateful = False

    def __init__(self, config: TargetConfig):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        if not self.base_url.endswith("/chat/completions"):
            self.base_url += "/chat/completions"

    def new_session(self) -> str:
        return ""

    def send(self, session: str, messages: list[dict]) -> TargetReply:
        headers = {"Content-Type": "application/json", **self.config.extra_headers}
        payload = {"model": self.config.model, "messages": messages}
        started = time.monotonic()
        resp = _post_chat(self.config, self.base_url, headers, payload)
        reply = _to_reply(resp, session)
        _ = started  # latency comes from requests' own timer
        return reply


class SessionTarget(OpenAIChatTarget):
    """Stateful variant: a fresh session id per `new_session()`, sent on every
    request via `session_header`. Cross-session probes (objective
    `secret-echo` run under the `cross-session` strategy) plant in one session
    and collect in another — the EchoLeak-class persistence check that only
    makes sense against a server that remembers."""

    stateful = True

    def __init__(self, config: TargetConfig):
        super().__init__(config)
        self._header_name = config.session_header or "X-Session-Id"

    def new_session(self) -> str:
        return uuid.uuid4().hex

    def send(self, session: str, messages: list[dict]) -> TargetReply:
        headers = {"Content-Type": "application/json", **self.config.extra_headers}
        if session:
            headers[self._header_name] = session
        payload = {"model": self.config.model, "messages": messages}
        resp = _post_chat(self.config, self.base_url, headers, payload)
        return _to_reply(resp, session)


class ScriptedTarget:
    """Deterministic in-process target for offline validation and tests.

    rules: a list of (needle, reply) pairs checked against the last user message,
    case-insensitively, first match wins; `default_reply` otherwise. Because the
    reply is fixed per trigger, a scripted target can simulate "leaks only under
    the base64 encoding" or "leaks only across sessions" exactly — which is how
    the campaign/bandit/regression logic is tested without a network.
    """

    def __init__(self, config: TargetConfig, rules: list[tuple[str, str]] | None = None,
                 default_reply: str = "I'm sorry, but I can't help with that.",
                 stateful: bool = False,
                 fn_rules: list | None = None):
        if config.kind != "scripted":
            raise TargetAuthError("ScriptedTarget requires kind='scripted'")
        self.config = config
        self.stateful = stateful
        self.rules = list(rules or [])
        # Dynamic rules: fn(last_user_text, session_id, messages) -> reply or None,
        # checked before the static ones. The full conversation and session id are
        # passed so tests can model session-scoped or persistent memory ("echoes
        # whatever code it was told, remembers it across sessions") without
        # knowing canaries in advance.
        self.fn_rules = list(fn_rules or [])
        self.default_reply = default_reply
        self.turns: list[dict] = []          # everything sent, for assertions
        self._sessions = 0

    def new_session(self) -> str:
        self._sessions += 1
        return f"scripted-session-{self._sessions}"

    def send(self, session: str, messages: list[dict]) -> TargetReply:
        self.turns.append({"session": session, "messages": messages})
        last_user = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            "")
        reply = None
        for fn in self.fn_rules:
            reply = fn(last_user, session, messages)
            if reply is not None:
                break
        if reply is None:
            low = last_user.lower()
            reply = self.default_reply
            for needle, r in self.rules:
                if needle.lower() in low:
                    reply = r
                    break
        return TargetReply(text=reply, status=200, latency_ms=0, session_id=session)


NETWORK_KINDS = {"openai_chat": OpenAIChatTarget, "session": SessionTarget}


def target_from_config(config: TargetConfig, *, scripted_rules=None,
                       scripted_default=None, scripted_stateful=False):
    """Build the right target class for a validated config."""
    if config.kind == "scripted":
        return ScriptedTarget(config, rules=scripted_rules,
                              default_reply=scripted_default,
                              stateful=scripted_stateful)
    cls = NETWORK_KINDS.get(config.kind)
    if cls is None:
        raise TargetAuthError(f"unknown target kind {config.kind!r}")
    return cls(config)
