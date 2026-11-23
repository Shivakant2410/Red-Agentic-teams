"""Out-of-band interaction oracle — the missing listener for BLIND vulns.

Synchronous HTTP predicates (proof.py) cannot prove blind SSRF, blind XXE,
blind/stored XSS that fires elsewhere, DNS exfiltration, or asynchronous command
execution: the proof is a callback the TARGET makes to a server WE control, not
anything in the HTTP response we hold. This module is that server.

Model (operator chose Interactsh public transport, 2026-11-23): mint a unique
canary domain, embed it in a payload (SSRF url, XXE entity, `nslookup $(canary)`,
XSS beacon), fire the payload through the normal tools, then poll whether the
canary received a DNS/HTTP interaction. A deterministic `oob_callback` predicate
in proof.py turns "the canary was hit" into a reproducible CheckOutcome, so a
blind finding flows through the SAME verify_finding_independently pipeline as
every other proof — no LLM opinion, no hallucinated blind bug.

SAFETY / PRIVACY: a public collaborator (oast.pro) means canary subdomains and
any data the target leaks INTO the callback transit a third party. That breaks
strict data-handling (e.g. a GDPR engagement). So the transport is PLUGGABLE:
  RED_OOB_SERVER=<host>   point at a self-hosted Interactsh (keeps data yours)
  RED_OOB_ENABLE_PUBLIC=1 opt IN to the public default (off unless set)
With neither set, minting refuses rather than silently shipping data off-box.
The agent must only ever place canaries against IN-SCOPE targets.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


_DEFAULT_PUBLIC = "oast.pro"


@dataclass
class Interaction:
    """One callback the target made to a canary we minted."""
    canary: str
    protocol: str          # "dns" | "http" | ...
    remote_addr: str = ""
    raw: str = ""
    ts: float = field(default_factory=time.time)


class OOBError(RuntimeError):
    pass


class OOBOracle:
    """Run-scoped OOB listener. Lives on ToolContext (like `proxy`); mint/poll
    are exposed to the agent as tools, and proof.py's oob_callback predicate
    reads `interactions_for()`.

    Transport is an injected bridge so the public Interactsh client, a
    self-hosted one, or a local HTTP/DNS listener are interchangeable. The
    default resolves from env (see module docstring) and FAILS CLOSED — minting
    without a configured transport refuses rather than leaking off-box.
    """

    def __init__(self, bridge: "OOBBridge | None" = None, audit=None):
        self._bridge = bridge if bridge is not None else _bridge_from_env()
        self._audit = audit
        self._canaries: set[str] = set()
        self._cache: list[Interaction] = []
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self._bridge is not None and self._bridge.ready

    def mint(self, label: str = "") -> str:
        """Return a fresh unique canary domain to embed in a payload."""
        if not self.available:
            raise OOBError(
                "OOB oracle not configured. Set RED_OOB_SERVER=<self-hosted "
                "interactsh host> (keeps callback data yours), or "
                "RED_OOB_ENABLE_PUBLIC=1 to opt into the public oast.pro "
                "collaborator. Refusing to mint — fail closed, not ship data "
                "to a third party silently.")
        canary = self._bridge.new_canary()
        with self._lock:
            self._canaries.add(canary.lower())
        if self._audit is not None:
            # Record the NON-secret fact: a canary was minted and for what.
            self._audit.record("oob.mint", canary=canary, label=label[:120],
                               transport=self._bridge.name)
        return canary

    def poll(self) -> list[Interaction]:
        """Pull new interactions from the transport and merge into the cache."""
        if not self.available:
            return []
        try:
            fresh = self._bridge.poll()
        except Exception as exc:  # noqa: BLE001
            if self._audit is not None:
                self._audit.record("oob.poll_error", error=str(exc)[:200])
            return []
        with self._lock:
            # Keep only interactions whose canary we actually minted (the public
            # server is shared — ignore anyone else's noise).
            mine = [i for i in fresh
                    if any(c in i.canary.lower() for c in self._canaries)]
            self._cache.extend(mine)
            out = list(self._cache)
        if mine and self._audit is not None:
            self._audit.record("oob.interactions", count=len(mine),
                               protocols=sorted({i.protocol for i in mine}))
        return out

    def interactions_for(self, canary: str, *, protocol: str = "") -> list[Interaction]:
        """All interactions seen for a given canary (optionally one protocol).
        Polls first so a just-fired payload's callback is caught."""
        self.poll()
        key = (canary or "").lower()
        with self._lock:
            return [i for i in self._cache
                    if key and key in i.canary.lower()
                    and (not protocol or i.protocol == protocol)]

    def close(self) -> None:
        if self._bridge is not None:
            try:
                self._bridge.close()
            except Exception:
                pass


# -- transport bridges -------------------------------------------------------

class OOBBridge:
    """Transport interface: anything that can mint canaries and report callbacks.
    Concrete bridges: InteractshBridge (public or self-hosted). A local HTTP/DNS
    listener bridge can be added later behind this same interface."""
    name = "none"
    ready = False

    def new_canary(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def poll(self) -> list[Interaction]:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        pass


class InteractshBridge(OOBBridge):
    """Interactsh client (public oast.pro by default, or a self-hosted server).

    Interactsh registers an RSA public key with the server and receives
    AES-encrypted interaction blobs it decrypts locally. To avoid a hard crypto
    dependency when the `interactsh-client` library isn't installed, this bridge
    prefers the installed python client if present and otherwise degrades to a
    minimal correlation-id mode against the server's poll endpoint.
    """

    def __init__(self, server: str, token: str = ""):
        self.name = f"interactsh:{server}"
        self._server = server
        self._token = token
        self._client = None
        self._correlation = secrets.token_hex(10)  # 20-char like interactsh
        self.ready = False
        self._init_client()

    def _init_client(self) -> None:
        # Prefer the real client when available (full crypto + DNS/HTTP).
        try:
            from interactsh import Interactsh  # type: ignore
            self._client = Interactsh(server=self._server, token=self._token or None)
            self.ready = True
            self.name = f"interactsh-lib:{self._server}"
            return
        except Exception:
            self._client = None
        # Degraded mode still needs requests to talk to the server.
        self.ready = requests is not None

    def new_canary(self) -> str:
        if self._client is not None:
            try:
                return self._client.get_interactsh_url()  # type: ignore[attr-defined]
            except Exception:
                pass
        # Degraded: a correlation subdomain on the server. (DNS/HTTP hits to it
        # still register server-side; full decryption needs the lib, so degraded
        # mode is best-effort and documented as such.)
        rand = secrets.token_hex(4)
        return f"{self._correlation}{rand}.{self._server}"

    def poll(self) -> list[Interaction]:
        if self._client is not None:
            out: list[Interaction] = []
            try:
                for ev in (self._client.poll() or []):  # type: ignore[attr-defined]
                    out.append(Interaction(
                        canary=str(ev.get("full-id") or ev.get("unique-id") or ""),
                        protocol=str(ev.get("protocol") or "").lower(),
                        remote_addr=str(ev.get("remote-address") or ""),
                        raw=str(ev.get("raw-request") or "")[:2000]))
            except Exception:
                return []
            return out
        return []   # degraded mode cannot decrypt server blobs without the lib

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.deregister()  # type: ignore[attr-defined]
            except Exception:
                pass


def _bridge_from_env() -> OOBBridge | None:
    """Resolve a transport from env, FAIL CLOSED (None) when nothing is set so
    the oracle refuses to ship data to a third party by default."""
    server = os.environ.get("RED_OOB_SERVER", "").strip()
    token = os.environ.get("RED_OOB_TOKEN", "").strip()
    if server:
        return InteractshBridge(server, token)   # self-hosted: data stays yours
    if os.environ.get("RED_OOB_ENABLE_PUBLIC", "").strip() in ("1", "true", "yes"):
        return InteractshBridge(_DEFAULT_PUBLIC, token)   # explicit opt-in
    return None
