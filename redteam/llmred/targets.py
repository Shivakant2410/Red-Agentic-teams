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
  - AgenticLoopTarget — the agentic adapter: wraps a REAL tool-calling loop (the
                        caller supplies the harness — the agent under test) and
                        records every actual tool invocation (name + arguments
                        + session). This is what lets verdicts measure what an
                        agent DID instead of what it said.

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


def _raise_for_status(resp: requests.Response) -> None:
    """The module's single HTTP-status contract: 429 -> TargetRateLimited (with
    the Retry-After hint), any other >=400 -> TargetError. Shared by every
    target and harness that rides on _post_chat, so 429 backoff semantics
    cannot drift between them."""
    if resp.status_code == 429:
        retry = resp.headers.get("Retry-After")
        try:
            raise TargetRateLimited(float(retry) if retry else None)
        except (TypeError, ValueError):
            raise TargetRateLimited(None) from None
    if resp.status_code >= 400:
        raise TargetError(f"HTTP {resp.status_code}: {resp.text[:300]}")


def _to_reply(resp: requests.Response, session: str) -> TargetReply:
    _raise_for_status(resp)
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

    latency_fn: optional (last_user_text, session_id) -> milliseconds. The B2
    timing instruments measure TargetReply.latency_ms as their side-channel
    observable, so offline proofs need a deterministic latency source; network
    targets carry requests' own elapsed time. None (default) keeps the
    historic 0 — no existing behavior changes.
    """

    def __init__(self, config: TargetConfig, rules: list[tuple[str, str]] | None = None,
                 default_reply: str = "I'm sorry, but I can't help with that.",
                 stateful: bool = False,
                 fn_rules: list | None = None,
                 latency_fn=None):
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
        self.latency_fn = latency_fn
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
        latency = (int(self.latency_fn(last_user, session))
                   if self.latency_fn is not None else 0)
        return TargetReply(text=reply, status=200, latency_ms=latency,
                           session_id=session)


# -- agentic targets (the B1 adapter) ------------------------------------------

@dataclass(frozen=True)
class ToolInvocation:
    """One observed tool call: what ran, with what arguments, in which session.
    Recorded by AgenticLoopTarget from the harness's own report — never
    inferred from reply text."""

    tool: str
    arguments: dict
    session: str
    seq: int = 0

    @property
    def args_text(self) -> str:
        """Canonical lowercase-friendly argument text for deterministic
        predicates (sorted keys, so equivalent args match equivalently)."""
        try:
            return json.dumps(self.arguments, sort_keys=True, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(self.arguments)


@dataclass
class AgentRun:
    """What a harness reports for one turn: the agent's final text PLUS the
    ordered list of tool calls it actually made. `final_text` alone would
    recreate the says-vs-does gap this adapter exists to close."""

    final_text: str = ""
    tool_calls: list = field(default_factory=list)   # [(tool_name, arguments_dict), ...]
    truncated: bool = False                          # loop hit the round cap


class AgentHarness(Protocol):
    """The agent under test, reduced to the one seam the adapter needs. A
    production harness drives a real model + real tools (see OpenAIToolLoop);
    tests supply a deterministic double. The harness owns its model access and
    its tool implementations — the adapter only observes."""

    def run(self, messages: list[dict]) -> AgentRun: ...


class AgenticLoopTarget:
    """Wraps a real tool-calling agent loop and records actual tool invocations
    (name + parsed arguments + session). This is the module's answer to the
    agentic detection gap: chat-shaped targets can only show what the model
    SAID, so a compliance token was the best available evidence. An agent
    target can show what it DID — and action evidence outranks text evidence
    in the verdict order (campaign._final_verdict).

    Fail-closed notes:
      - The harness is the agent under test; the adapter never invents, filters
        or reorders tool calls, and never executes anything itself.
      - A harness that raises is surfaced as TargetError (an error record, not
        a crash and not a silent defense).
      - Authorization is enforced by TargetConfig exactly as for every other
        kind; kind='agentic' requires no network fields because the harness
        owns its own model access (OpenAIToolLoop re-checks them itself).
    """

    def __init__(self, config: TargetConfig, harness: AgentHarness,
                 stateful: bool = True):
        if config.kind != "agentic":
            raise TargetAuthError("AgenticLoopTarget requires kind='agentic'")
        self.config = config
        self._harness = harness
        # Whether the DEPLOYED agent carries state across sessions is a
        # property of the deployment, so the caller declares it; it gates the
        # cross-session strategy exactly as for SessionTarget.
        self.stateful = stateful
        self.invocations: list[ToolInvocation] = []
        self._seq = 0

    def new_session(self) -> str:
        return uuid.uuid4().hex

    @property
    def harness(self):
        """The wrapped agent under test (read access for the B2 dynamics
        layer: propagation chains need the harness to drive additional hops).
        The adapter still only ever OBSERVES it."""
        return self._harness

    def send(self, session: str, messages: list[dict]) -> TargetReply:
        started = time.monotonic()
        try:
            run = self._harness.run(messages)
        except (TargetRateLimited, TargetAuthError):
            # Transport signals must reach the campaign unwrapped: 429 drives
            # the backoff/retry contract, allowlist violations must stay loud.
            raise
        except Exception as exc:      # harness failure is an error, not a defense
            raise TargetError(f"agent harness failed: {exc}") from exc
        latency = int((time.monotonic() - started) * 1000)
        for name, args in (run.tool_calls or []):
            self._seq += 1
            self.invocations.append(ToolInvocation(
                tool=str(name), arguments=dict(args or {}),
                session=session, seq=self._seq))
        return TargetReply(text=run.final_text or "", status=200,
                           latency_ms=latency, session_id=session)

    def tool_invocations(self, session: str | None = None) -> list[ToolInvocation]:
        """The recorded action evidence, optionally scoped to one session. The
        campaign reads this after each attempt; detectors match conditions
        against it deterministically."""
        invs = self.invocations
        if session is not None:
            invs = [i for i in invs if i.session == session]
        return list(invs)


class OpenAIToolLoop:
    """A real tool-calling loop for an agent whose BRAIN is an OpenAI-
    compatible chat endpoint and whose HANDS are owner-supplied tools.

    tools:    the agent's REAL declared tool schema (OpenAI function-tool
              shape). The harness must not invent tools beyond this list —
              measuring a tool surface the deployment doesn't have would be
              self-deception, the exact failure mode B1 exists to remove.
    executor: callable(name, arguments_dict) -> str result. These are the
              owner's actual tool implementations; an executor that raises is
              recorded as a tool error result and the loop continues (honest
              transcript, no hidden failure).

    Every brain call goes through _post_chat, so the host allowlist is
    re-checked per call, and 429/HTTP-error semantics are identical to the
    chat targets. The round cap bounds the loop; a loop that exhausts it
    returns truncated=True with the calls collected so far — evidence is
    kept, the attempt is not silently cut."""

    def __init__(self, config: TargetConfig, tools: list[dict],
                 executor, max_rounds: int = 6):
        if config.kind != "agentic":
            raise TargetAuthError("OpenAIToolLoop requires kind='agentic'")
        if not config.base_url.startswith(("http://", "https://")):
            raise TargetAuthError(
                f"harness for {config.name!r}: brain endpoint needs an "
                "http(s) base_url")
        if not config.model:
            raise TargetAuthError(f"harness for {config.name!r}: 'model' is required")
        # Fail-closed rule 2 applies to the brain endpoint too.
        if not config.allowed_hosts:
            raise TargetAuthError(
                f"harness for {config.name!r}: allowed_hosts must name the "
                "brain endpoint's host(s)")
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        if not self.base_url.endswith("/chat/completions"):
            self.base_url += "/chat/completions"
        self.tools = list(tools or [])
        self._executor = executor
        self.max_rounds = max(1, int(max_rounds))

    def run(self, messages: list[dict]) -> AgentRun:
        convo = [dict(m) for m in messages]
        calls: list[tuple[str, dict]] = []
        for _round in range(self.max_rounds):
            payload = {"model": self.config.model, "messages": convo,
                       "tools": self.tools}
            resp = _post_chat(self.config, self.base_url,
                              {"Content-Type": "application/json"}, payload)
            _raise_for_status(resp)
            try:
                msg = resp.json()["choices"][0]["message"]
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise TargetError(f"unrecognized response body: {exc}") from exc
            requested = msg.get("tool_calls") or []
            if not requested:
                return AgentRun(final_text=msg.get("content") or "",
                                tool_calls=calls, truncated=False)
            convo.append({"role": "assistant",
                          "content": msg.get("content") or "",
                          "tool_calls": requested})
            for tc in requested:
                fn = tc.get("function") or {}
                name = str(fn.get("name") or "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                    if not isinstance(args, dict):
                        args = {"_raw": args}
                except ValueError:
                    args = {"_raw": fn.get("arguments")}
                calls.append((name, args))
                try:
                    result = self._executor(name, args)
                except Exception as exc:
                    result = f"tool error: {exc}"
                convo.append({"role": "tool",
                              "tool_call_id": str(tc.get("id") or ""),
                              "content": str(result)[:4000]})
        return AgentRun(final_text="", tool_calls=calls, truncated=True)


NETWORK_KINDS = {"openai_chat": OpenAIChatTarget, "session": SessionTarget}


def target_from_config(config: TargetConfig, *, scripted_rules=None,
                       scripted_default=None, scripted_stateful=False):
    """Build the right target class for a validated config."""
    if config.kind == "agentic":
        raise TargetAuthError(
            "kind 'agentic' wraps a real tool-calling loop and needs a harness: "
            "construct AgenticLoopTarget(config, harness) directly (or pass a "
            "target_factory to the campaign) — it cannot be built from config "
            "alone")
    if config.kind == "scripted":
        return ScriptedTarget(config, rules=scripted_rules,
                              default_reply=scripted_default,
                              stateful=scripted_stateful)
    cls = NETWORK_KINDS.get(config.kind)
    if cls is None:
        raise TargetAuthError(f"unknown target kind {config.kind!r}")
    return cls(config)
