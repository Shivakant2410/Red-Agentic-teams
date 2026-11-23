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
  RED_OOB_TOKEN=<token>   the server's -token / -auth value, if set
  RED_OOB_ENABLE_PUBLIC=1 opt IN to the public default (off unless set)
With neither set, minting refuses rather than silently shipping data off-box.
The agent must only ever place canaries against IN-SCOPE targets.

TRANSPORT: there is no maintained pip-installable Python Interactsh client, so
InteractshBridge implements the protocol natively (register/poll/decrypt) with
only `cryptography` + `requests` — no third-party dependency in a security tool.
For Vinted and any GDPR engagement, self-host the ProjectDiscovery interactsh
server (`go install .../interactsh-server@latest`) and set RED_OOB_SERVER to it,
so callback data never transits a third party.
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
    """Native Interactsh client — implements the register/poll/decrypt protocol
    directly against a (preferably self-hosted) ProjectDiscovery interactsh
    server, with NO third-party Python dependency (there is no maintained one on
    PyPI). Uses only `cryptography` + `requests`.

    Protocol (from pkg/client/client.go):
      register: POST /register {public-key (b64 of PEM "RSA PUBLIC KEY" of PKIX
        DER), secret-key (uuid4), correlation-id (20-char)}; Authorization: token.
      poll:     GET /poll?id=<cid>&secret=<secret> -> {data[], aes_key, extra[],
        tlddata[]}. aes_key is RSA-OAEP(SHA-256) wrapped; each data entry is
        base64( iv[16] || AES-CTR ciphertext ).
      canary:   <correlation-id><zbase32 nonce>.<server host>
    """

    def __init__(self, server: str, token: str = ""):
        self.name = f"interactsh:{server}"
        self._server_host = server
        self._base = server if server.startswith("http") else f"https://{server}"
        self._token = token
        self._cid = _new_correlation_id()
        self._secret = _uuid4()
        self._priv = None
        self._registered = False
        self.ready = False
        self._register()

    # -- crypto + registration ----------------------------------------------

    def _register(self) -> None:
        if requests is None:
            return
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            return
        try:
            self._priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            der = self._priv.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            b64der = base64.b64encode(der).decode()
            pem = ("-----BEGIN RSA PUBLIC KEY-----\n"
                   + "\n".join(b64der[i:i + 64] for i in range(0, len(b64der), 64))
                   + "\n-----END RSA PUBLIC KEY-----\n")
            pub_field = base64.b64encode(pem.encode()).decode()
            headers = {"Authorization": self._token} if self._token else {}
            r = requests.post(f"{self._base}/register", json={
                "public-key": pub_field, "secret-key": self._secret,
                "correlation-id": self._cid}, headers=headers, timeout=10)
            self._registered = (r.status_code == 200)
            self.ready = self._registered
        except Exception:
            self.ready = False

    def new_canary(self) -> str:
        # <cid(20)><nonce(13)>.<host>. The nonce only needs to be a lowercase
        # alphanumeric string of the right length; the server keys on the first
        # 20 chars (the correlation id), which is how our interactions match.
        nonce = _zbase32_like(13)
        host = self._server_host.split("//")[-1]  # strip scheme if present
        return f"{self._cid}{nonce}.{host}"

    def poll(self) -> list[Interaction]:
        if not self._registered or requests is None or self._priv is None:
            return []
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        headers = {"Authorization": self._token} if self._token else {}
        r = requests.get(f"{self._base}/poll", params={"id": self._cid, "secret": self._secret},
                         headers=headers, timeout=10)
        if r.status_code != 200:
            return []
        body = r.json()
        out: list[Interaction] = []
        # Encrypted interactions.
        data = body.get("data") or []
        aes_key_b64 = body.get("aes_key") or ""
        if data and aes_key_b64:
            try:
                key = self._priv.decrypt(
                    base64.b64decode(aes_key_b64),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                 algorithm=hashes.SHA256(), label=None))
                for item in data:
                    raw = base64.b64decode(item)
                    if len(raw) < 16:
                        continue
                    iv, ct = raw[:16], raw[16:]
                    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
                    plain = (dec.update(ct) + dec.finalize()).rstrip(b" \t\r\n")
                    out.append(self._to_interaction(plain))
            except Exception:
                pass
        # Plaintext interactions (auth-token / root-TLD modes).
        for s in (body.get("extra") or []) + (body.get("tlddata") or []):
            try:
                out.append(self._to_interaction(s.encode() if isinstance(s, str) else s))
            except Exception:
                continue
        return out

    @staticmethod
    def _to_interaction(plain: bytes) -> Interaction:
        import json as _json
        d = _json.loads(plain)
        return Interaction(
            canary=str(d.get("full-id") or d.get("unique-id") or d.get("fullId")
                       or d.get("uniqueId") or ""),
            protocol=str(d.get("protocol") or "").lower(),
            remote_addr=str(d.get("remote-address") or d.get("remoteAddress") or ""),
            raw=str(d.get("raw-request") or d.get("rawRequest") or "")[:2000])

    def close(self) -> None:
        if not self._registered or requests is None:
            return
        try:
            headers = {"Authorization": self._token} if self._token else {}
            requests.post(f"{self._base}/deregister",
                          json={"correlation-id": self._cid, "secret-key": self._secret},
                          headers=headers, timeout=10)
        except Exception:
            pass


# xid uses the alphabet [0-9a-v]; the server only needs a 20-char lowercase id.
_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"


def _new_correlation_id(length: int = 20) -> str:
    return "".join(secrets.choice(_XID_ALPHABET) for _ in range(length))


def _zbase32_like(length: int) -> str:
    # zbase32 alphabet; any lowercase alphanumeric of the right length works for
    # matching (the server keys on the correlation-id prefix, not the nonce).
    alpha = "ybndrfg8ejkmcpqxot1uwisza345h769"
    return "".join(secrets.choice(alpha) for _ in range(length))


def _uuid4() -> str:
    import uuid
    return str(uuid.uuid4())


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
