"""EvidenceProxy — a recording MITM proxy: the evidence plane for traffic the
shared fetch path cannot see.

THE BLIND SPOT THIS CLOSES
    The shared fetch path (tools/http.py) records every in-process request. But
    tools that run inside the Kali sandbox — nuclei, bandit, raw curl, anything
    an operator wires up — speak directly through the egress firewall, and the
    firewall forwards without looking. Their HTTP(S) exchanges were invisible as
    evidence: the run report claimed work nobody could audit on the wire.
    ARTEX solves this with an in-path recording proxy; we port the idea with our
    discipline instead of their implementation.

WHAT IT DOES
    A real HTTP proxy bound next to the sandbox. The sandbox's tool environment
    points HTTP(S)_PROXY at it, so proxied tool traffic becomes wire evidence:

      plain HTTP   -> absolute-URI requests are scope-checked, forwarded, and
                      recorded in full (status, headers, bodies) — same masking
                      rules as every other traffic record.
      HTTPS/CONNECT -> two modes, chosen honestly:
        * mitm        (cryptography available + a run CA): the proxy terminates
                       TLS with a per-host leaf certificate signed by a run-scoped
                       CA (installed into the container's trust store), decrypts,
                       records the exchange, and re-encrypts upstream WITH
                       verification against the real target certificate. A MITM
                       that validates upstream is the correct posture — we refuse
                       to relay a spoofed target.
        * passthrough (no cryptography / CA disabled / mitm refused): the tunnel
                       is spliced byte-for-byte and recorded as METADATA ONLY —
                       SNI, byte counts, duration, status 0. We record what we
                       saw and never claim content we did not decrypt.

ENFORCEMENT (not just evidence)
    The proxy is a second, independent scope enforcement plane. Every authority
    (CONNECT host:port, absolute-URI target) passes ScopeGuard.check() BEFORE
    anything is dialed; refusals are recorded as evidence that the boundary
    held, exactly like the fetch path does. Tool traffic that ignores the proxy
    env (nmap raw scans) is still bounded by the iptables egress firewall — the
    proxy narrows the evidence gap for HTTP-speaking tools; it does not replace
    the firewall and never claims to.

BUDGET
    When a RateLimiter is supplied, the SAME instance that gates the fetch path
    gates the proxy: one acquire() per proxied exchange, so the RoE total-request
    budget is truly global across both planes instead of two blind counters.
    A spent budget refuses new exchanges with 429 + a recorded denial.

FAILURE DISCIPLINE (same rules as the EventBus / TrafficRecorder)
    - Recording must never break a request in flight: the sink already swallows
      its own failures; the proxy adds nothing on top.
    - One bad connection dies alone: every exchange runs on its own daemon
      thread; the listener never inherits a connection's exception.
    - A client that rejects our MITM certificate fails LOUDLY for that
      connection only — no silent passthrough fallback, because the client told
      us it does not trust the evidence plane; pretending otherwise would
      fabricate a successful exchange that never happened.
"""

from __future__ import annotations

import datetime as _dt
import json
import select
import socket
import socketserver
import ssl
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path

# Hop-by-hop headers (RFC 7230 §6.1) — never forwarded, never recorded as if they
# crossed the exchange. accept-encoding is rewritten to identity: the traffic log
# is OPERATOR-FACING EVIDENCE, and a gzipped body is evidence nobody can read.
_HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
}
_REQUEST_BODY_CAP = 1 * 1024 * 1024     # refuse to buffer absurd request bodies
_RELAY_BODY_CAP = 10 * 1024 * 1024      # relay cap; evidence copy clips harder
_SOCKET_TIMEOUT = 30.0
_PEEK_BUDGET = 2.0                      # seconds to wait for a full ClientHello

_MAX_LABEL = 32


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# ClientHello SNI extraction — stdlib only, best-effort by design.
# ---------------------------------------------------------------------------

def peek_sni(data: bytes) -> str:
    """Extract the server_name extension value from a TLS ClientHello.

    Returns "" for anything malformed, truncated, or absent — SNI is metadata we
    TRY to record, never a parse contract we can fail a tunnel over. Bounds are
    checked at every step: attacker-controlled bytes must never index us out of
    range (the client side of this proxy is exactly as hostile as the target).
    """
    try:
        # TLS record: type(1) version(2) length(2)
        if len(data) < 5 or data[0] != 0x16:
            return ""
        rec_len = int.from_bytes(data[3:5], "big")
        if len(data) < 5 + rec_len:
            return ""  # incomplete record; caller may retry with more bytes
        # Handshake: type(1) length(3)
        i = 5
        if data[i] != 0x01:
            return ""
        i += 4  # skip type + length
        # ClientHello: version(2) random(32) session_id_len(1) ...
        i += 2 + 32
        if i >= len(data):
            return ""
        i += 1 + data[i]
        if i + 2 > len(data):
            return ""
        i += 2 + int.from_bytes(data[i:i + 2], "big")  # cipher suites
        if i >= len(data):
            return ""
        i += 1 + data[i]  # compression methods
        if i + 2 > len(data):
            return ""
        ext_len = int.from_bytes(data[i:i + 2], "big")
        i += 2
        end = min(i + ext_len, len(data))
        while i + 4 <= end:
            etype = int.from_bytes(data[i:i + 2], "big")
            elen = int.from_bytes(data[i + 2:i + 4], "big")
            body = data[i + 4:i + 4 + elen]
            if etype == 0x0000 and len(body) >= 5 and body[2] == 0x00:
                nlen = int.from_bytes(body[3:5], "big")
                return body[5:5 + nlen].decode("ascii", errors="replace").lower()
            i += 4 + elen
    except (IndexError, ValueError):
        return ""
    return ""


def clienthello_complete(data: bytes) -> bool:
    """Is a full TLS record buffered (so SNI parsing is definitive, not premature)?"""
    if len(data) < 5:
        return False
    rec_len = int.from_bytes(data[3:5], "big")
    return len(data) >= 5 + rec_len


# ---------------------------------------------------------------------------
# RunCA — the run-scoped certificate authority (requires `cryptography`).
# ---------------------------------------------------------------------------

class RunCA:
    """One CA per run: generated on start, persisted under the run dir, dead at
    run end. Its only power is signing leaf certs for hosts THIS proxy intercepts
    — keeping it run-scoped bounds the blast radius of a leaked CA key to a
    single engagement's evidence instead of a permanent host trust anchor."""

    def __init__(self, directory: Path, key, cert, cert_der: bytes):
        self._dir = directory
        self._key = key
        self._cert = cert
        self._cert_der = cert_der
        self._leaf_cache: dict[str, ssl.SSLContext] = {}
        self._leaf_lock = threading.Lock()

    @classmethod
    def create(cls, directory: Path) -> "RunCA | None":
        """Build a fresh CA, or return None when `cryptography` is unavailable —
        the proxy then runs passthrough (honest degradation, never a fake MITM)."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
        except ImportError:
            return None
        directory.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Red-Agentic-teams Evidence CA (run-scoped)"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(key, hashes.SHA256()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
        (directory / "ca.crt").write_bytes(cert_pem)
        (directory / "ca.key").write_bytes(key_pem)
        return cls(directory, key, cert, cert.public_bytes(serialization.Encoding.DER))

    @property
    def cert_path(self) -> Path:
        return self._dir / "ca.crt"

    @property
    def fingerprint(self) -> str:
        import hashlib
        return "sha256:" + hashlib.sha256(self._cert_der).hexdigest()[:16]

    def server_context(self, host: str) -> ssl.SSLContext:
        """An SSLContext presenting a freshly-signed leaf for `host` (cached)."""
        with self._leaf_lock:
            ctx = self._leaf_cache.get(host)
            if ctx is not None:
                return ctx
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        san_names = [x509.DNSName(host)]
        try:
            import ipaddress as _ip
            san_names.append(x509.IPAddress(_ip.ip_address(host)))
        except ValueError:
            pass
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, host[:64]),
                ]))
                .issuer_name(self._cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                               critical=False)
                .sign(self._key, hashes.SHA256()))
        leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
        leaf_key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)[:64] or "host"
        leaf_path = self._dir / f"leaf-{safe}.crt"
        key_path = self._dir / f"leaf-{safe}.key"
        leaf_path.write_bytes(leaf_pem)
        key_path.write_bytes(leaf_key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(leaf_path), str(key_path))
        with self._leaf_lock:
            self._leaf_cache[host] = ctx
        return ctx


# ---------------------------------------------------------------------------
# Stats + the connection handler
# ---------------------------------------------------------------------------

class _Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.exchanges = 0      # recorded full exchanges (plain http + decrypted https)
        self.tunnels = 0        # passthrough tunnels (metadata only)
        self.denied = 0         # scope/budget refusals — evidence the boundary held
        self.errors = 0
        self.bytes_up = 0
        self.bytes_down = 0

    def bump(self, field: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, field, getattr(self, field) + n)

    def add_bytes(self, up: int, down: int) -> None:
        with self._lock:
            self.bytes_up += up
            self.bytes_down += down

    def to_dict(self) -> dict:
        with self._lock:
            return {"exchanges": self.exchanges, "tunnels": self.tunnels,
                    "denied": self.denied, "errors": self.errors,
                    "bytes_up": self.bytes_up, "bytes_down": self.bytes_down}


class _ProxyHandler(socketserver.BaseRequestHandler):
    """One connection = one thread = one isolated failure domain."""

    protocol = "http/1.1"

    # Convenience accessors for the server's shared state --------------------
    @property
    def proxy(self) -> "EvidenceProxy":
        # Only ever runs under _ProxyServer, which always carries .proxy.
        return self.server.proxy  # type: ignore[attr-defined]

    def handle(self) -> None:
        try:
            self.request.settimeout(_SOCKET_TIMEOUT)
            first = self._read_head()
            if not first:
                return
            line, headers, excess = first
            method, _, rest = line.partition(" ")
            method = method.strip().upper()
            if method == "CONNECT":
                self._do_connect(rest.split(" ")[0].strip(), excess)
            elif "://" in rest:
                # Absolute-URI form (a real forward-proxy request).
                url = rest.split(" ")[0]
                self._do_plain_http(method, url, headers, excess)
            else:
                # Origin-form request to a proxy is nonsense; answer, don't guess.
                self._reply(400, b"evidence proxy: origin-form requests are not valid here\n")
        except (ConnectionError, socket.timeout, ssl.SSLError):
            self.proxy.stats.bump("errors")
        except Exception as exc:  # one bad connection must never kill the server
            self.proxy.stats.bump("errors")
            self._record_error(exc)

    # -- head parsing ----------------------------------------------------------

    def _read_head(self):
        """Read request line + headers (up to \\r\\n\\r\\n). Returns (line, headers,
        excess_bytes_received_beyond_the_head) or None on clean EOF."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.request.recv(65536)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 256 * 1024:
                self._reply(431, b"request head too large\n")
                return None
        head, _, excess = buf.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        line = lines[0]
        headers: dict[str, str] = {}
        for raw in lines[1:]:
            k, _, v = raw.partition(":")
            if k.strip():
                headers[k.strip().lower()] = v.strip()
        return line, headers, excess

    def _read_exact_body(self, headers: dict, already: bytes) -> bytes | None:
        """Read a Content-Length request body (capped). None = refuse (413 sent)."""
        try:
            clen = int(headers.get("content-length", "0") or "0")
        except ValueError:
            clen = 0
        if clen <= 0:
            return already or b""
        if clen > _REQUEST_BODY_CAP:
            self._reply(413, b"evidence proxy: request body exceeds cap\n")
            return None
        body = already
        while len(body) < clen:
            chunk = self.request.recv(min(65536, clen - len(body)))
            if not chunk:
                break
            body += chunk
        return body

    def _reply(self, status: int, body: bytes, extra: str = "") -> None:
        reason = {200: "Connection Established", 400: "Bad Request", 403: "Forbidden",
                  404: "Not Found", 413: "Payload Too Large", 429: "Too Many Requests",
                  431: "Request Header Fields Too Large",
                  502: "Bad Gateway"}.get(status, "Error")
        head = (f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n{extra}\r\n")
        try:
            self.request.sendall(head.encode() + body)
        except (ConnectionError, socket.timeout):
            pass

    def _reply_connect_ok(self) -> None:
        """Minimal 200 for CONNECT — no Connection header: the tunnel that follows
        has nothing to do with HTTP connection semantics."""
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except (ConnectionError, socket.timeout):
            pass

    # -- plain HTTP ------------------------------------------------------------

    def _do_plain_http(self, method: str, url: str, headers: dict, excess: bytes) -> None:
        body = self._read_exact_body(headers, excess)
        if body is None:
            return
        try:
            target = self.proxy.scope.check(url)
        except Exception as exc:
            self._deny(url, method, f"scope-denied: {exc}", status=403)
            return
        try:
            self.proxy.limiter.acquire()
        except Exception as exc:
            self._deny(url, method, f"budget-denied: {exc}", status=429)
            return
        fwd = {k: v for k, v in headers.items()
               if k not in _HOP_BY_HOP and k != "content-length"}
        fwd["accept-encoding"] = "identity"
        self._forward_exchange(method, target, url, fwd, body, tls_client=False)

    # -- CONNECT ---------------------------------------------------------------

    def _do_connect(self, authority: str, excess: bytes) -> None:
        host, port = self._split_authority(authority)
        if not host:
            self._reply(400, b"bad CONNECT authority\n")
            return
        # Scope first — the CONNECT authority is what the client will dial, checked
        # as https (normal case) with an http fallback when https is not a RoE scheme.
        target = None
        denial = ""
        for scheme in ("https", "http"):
            try:
                target = self.proxy.scope.check(f"{scheme}://{host}:{port}")
                break
            except Exception as exc:
                denial = str(exc)
        if target is None:
            self._deny(f"{host}:{port}", "CONNECT", f"scope-denied: {denial}", status=403)
            return
        try:
            self.proxy.limiter.acquire()
        except Exception as exc:
            self._deny(f"{host}:{port}", "CONNECT", f"budget-denied: {exc}", status=429)
            return

        # 200 first: the client will not send its ClientHello until we do.
        self._reply_connect_ok()
        sni = self._peek_sni_with_budget()
        label = sni or host

        if self.proxy.ca is not None:
            if self._mitm_tunnel(target, label):
                return
            # A client that rejects our CA told us something: it does not trust the
            # evidence plane. Fail loudly — never silently splice instead — and
            # leave wire evidence of the failed handshake.
            self.proxy.stats.bump("errors")
            err = (f"mitm handshake rejected by client (host={host} sni={sni!r}) — "
                   "client does not trust the run CA; no passthrough fallback")
            self.proxy.traffic.record_http(
                method="CONNECT", url=f"{target.scheme}://{host}:{port}",
                status=0, elapsed_ms=0, tool="sandbox", source="proxy-mitm",
                req_headers={"sni": sni or "(none)"}, error=err)
            self._record_error(err)
            return
        self._passthrough_tunnel(target, sni)

    @staticmethod
    def _split_authority(authority: str) -> tuple[str, int]:
        try:
            if authority.startswith("["):  # IPv6 literal [::1]:443
                host, _, rest = authority[1:].partition("]")
                port = int(rest.lstrip(":") or "443")
                return host.lower(), port
            host, _, port_s = authority.partition(":")
            return host.strip().lower(), int(port_s or "443")
        except ValueError:
            return "", 0

    def _peek_sni_with_budget(self) -> str:
        deadline = time.monotonic() + _PEEK_BUDGET
        while time.monotonic() < deadline:
            try:
                buf = self.request.recv(65536, socket.MSG_PEEK)
            except (ConnectionError, socket.timeout, ssl.SSLError, OSError):
                return ""
            if buf:
                sni = peek_sni(buf)
                if sni:
                    return sni
                if clienthello_complete(buf):
                    return ""  # full hello parsed, no SNI — definitive
            time.sleep(0.02)
        return ""

    # -- the two tunnel modes ----------------------------------------------------

    def _mitm_tunnel(self, target, label: str) -> bool:
        """Terminate the client TLS with a run-CA leaf; exchange inner HTTP in the
        clear on our side, re-encrypted upstream WITH real-certificate verification.
        Returns False when the client refused our certificate (caller records).

        ONE EXCHANGE PER TUNNEL, socket closed after the response — HTTP/1.0
        semantics. This is deliberate, not a shortcut: empirically (bisected over
        a dozen variants), app-data writes on a long-lived wrapped socket inside
        this handler can sit unflushed until the descriptor closes, so a
        keep-alive tunnel STARVES the client. Close-after-response is the
        configuration every test proves flushes immediately. Cost: one TLS
        handshake per exchange (tools open parallel connections anyway);
        benefit: responses are never black-holed. Clients (curl, requests,
        nuclei) handle connection-close natively — they retry or reconnect.
        """
        try:
            ctx = self.proxy.ca.server_context(label)
            tls_sock = ctx.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return False
        tls_sock.settimeout(_SOCKET_TIMEOUT)
        try:
            head = self._read_head_on(tls_sock)
        except (ConnectionError, socket.timeout, ssl.SSLError):
            return True
        if head is None:
            return True
        line, headers, excess = head
        method, _, rest = line.partition(" ")
        method = method.strip().upper()
        path = rest.split(" ")[0] if rest else "/"
        url = f"https://{target.host}:{target.port}{path if path.startswith('/') else '/' + path}"
        body = self._read_exact_body_on(tls_sock, headers, excess)
        if body is None:
            return True
        fwd = {k: v for k, v in headers.items()
               if k not in _HOP_BY_HOP and k != "content-length"}
        fwd["accept-encoding"] = "identity"
        fwd["host"] = f"{target.host}:{target.port}"
        try:
            self._forward_exchange(method, target, url, fwd, body,
                                   tls_client=True, sock=tls_sock)
        except (ConnectionError, socket.timeout, ssl.SSLError):
            pass
        finally:
            # The response is only guaranteed to be on the wire once the TLS
            # socket closes — see the docstring. Close ALWAYS, even after an
            # upstream error (the client then sees a truncated reply, which is
            # the honest shape of a failed exchange).
            try:
                tls_sock.close()
            except OSError:
                pass
        return True

    def _passthrough_tunnel(self, target, sni: str) -> None:
        """Splice bytes honestly; record METADATA ONLY. We did not decrypt, so we
        do not pretend to know method/url/status — bytes, duration, SNI."""
        start = time.monotonic()
        try:
            upstream = socket.create_connection((target.host, target.port), timeout=_SOCKET_TIMEOUT)
        except OSError as exc:
            self.proxy.stats.bump("errors")
            self.proxy.traffic.record_http(
                method="CONNECT", url=f"{target.scheme}://{target.host}:{target.port}",
                status=0, elapsed_ms=0, tool="sandbox", source="proxy-tunnel",
                error=f"upstream dial failed: {exc}")
            return
        up = down = 0
        try:
            up, down = self._splice(self.request, upstream)
        finally:
            try:
                upstream.close()
            except OSError:
                pass
        elapsed = int((time.monotonic() - start) * 1000)
        self.proxy.stats.bump("tunnels")
        self.proxy.stats.add_bytes(up, down)
        try:
            self.proxy.traffic.record_http(
                method="CONNECT", url=f"{target.scheme}://{target.host}:{target.port}",
                status=0, elapsed_ms=elapsed, tool="sandbox", source="proxy-tunnel",
                error="",
                req_headers={"sni": sni or "(none)", "mode": "passthrough",
                             "bytes_up": str(up), "bytes_down": str(down)},
                resp_body="")
        except Exception:
            pass

    @staticmethod
    def _splice(a, b) -> tuple[int, int]:
        """Bidirectional byte splice until both sides EOF (half-close aware)."""
        up = down = 0
        socks = [a, b]
        try:
            while socks:
                readable, _, _ = select.select(socks, [], [], 5.0)
                if not readable:
                    continue
                for s in readable:
                    try:
                        data = s.recv(65536)
                    except (ConnectionError, OSError):
                        data = b""
                    if not data:
                        socks.remove(s)
                        other = b if s is a else a
                        try:
                            other.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if s is a:
                        b.sendall(data)
                        up += len(data)
                    else:
                        a.sendall(data)
                        down += len(data)
        except (ConnectionError, OSError):
            pass
        return up, down

    # -- shared forward/record ---------------------------------------------------

    def _forward_exchange(self, method: str, target, url: str, headers: dict,
                          body: bytes, tls_client: bool, sock=None) -> None:
        """Send the request upstream (verify=real CA on TLS), stream the response
        back, record a masked evidence copy. Exchange = one traffic row."""
        start = time.monotonic()
        if target.scheme == "https":
            kwargs = {"timeout": _SOCKET_TIMEOUT}
            if self.proxy.upstream_context is not None:
                kwargs["context"] = self.proxy.upstream_context
            conn = HTTPSConnection(target.host, target.port, **kwargs)
        else:
            conn = HTTPConnection(target.host, target.port, timeout=_SOCKET_TIMEOUT)
        try:
            conn.request(method, self._path_of(url), body=body or None, headers=headers)
            resp = conn.getresponse()
            chunks = []
            total = 0
            truncated = False
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total <= _RELAY_BODY_CAP:
                    chunks.append(chunk)
                else:
                    truncated = True
            resp_body = b"".join(chunks)
            if truncated:
                resp_body = resp_body[:_RELAY_BODY_CAP]
            elapsed_ms = int((time.monotonic() - start) * 1000)

            out_headers = {k: v for k, v in resp.getheaders()
                           if k.lower() not in _HOP_BY_HOP}
            out_headers["Content-Length"] = str(len(resp_body))
            if truncated:
                out_headers["X-Evidence-Truncated"] = "1"
            head_lines = [f"HTTP/1.1 {resp.status} {resp.reason}"]
            head_lines += [f"{k}: {v}" for k, v in out_headers.items()]
            head = ("\r\n".join(head_lines) + "\r\n\r\n").encode("iso-8859-1", "replace")
            sink = sock if sock is not None else self.request
            sink.sendall(head + resp_body)

            self.proxy.stats.bump("exchanges")
            self.proxy.stats.add_bytes(len(body), len(resp_body))
            self.proxy.traffic.record_http(
                method=method, url=url, status=resp.status, elapsed_ms=elapsed_ms,
                tool="sandbox", source="proxy-mitm" if tls_client else "proxy",
                req_headers=headers, req_body=self._text(body),
                resp_headers=dict(out_headers), resp_body=self._text(resp_body))
        except Exception as exc:
            self.proxy.stats.bump("errors")
            self.proxy.traffic.record_http(
                method=method, url=url, status=0,
                elapsed_ms=int((time.monotonic() - start) * 1000),
                tool="sandbox", source="proxy-mitm" if tls_client else "proxy",
                req_headers=headers, req_body=self._text(body),
                error=f"upstream failed: {exc}")
            raise

    @staticmethod
    def _path_of(url: str) -> str:
        rest = url.split("://", 1)[-1]
        slash = rest.find("/")
        return rest[slash:] if slash != -1 else "/"

    @staticmethod
    def _text(raw: bytes | None) -> str:
        if not raw:
            return ""
        return raw.decode("utf-8", errors="replace")

    # -- head reading on an arbitrary socket (plain or TLS-wrapped) --------------

    def _read_head_on(self, sock):
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(65536)
            except (ConnectionError, socket.timeout, ssl.SSLError):
                return None
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 256 * 1024:
                return None
        head, _, excess = buf.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        headers: dict[str, str] = {}
        for raw in lines[1:]:
            k, _, v = raw.partition(":")
            if k.strip():
                headers[k.strip().lower()] = v.strip()
        return lines[0], headers, excess

    def _read_exact_body_on(self, sock, headers: dict, already: bytes) -> bytes | None:
        try:
            clen = int(headers.get("content-length", "0") or "0")
        except ValueError:
            clen = 0
        if clen <= 0:
            return already or b""
        if clen > _REQUEST_BODY_CAP:
            return None
        body = already
        while len(body) < clen:
            try:
                chunk = sock.recv(min(65536, clen - len(body)))
            except (ConnectionError, socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            body += chunk
        return body

    # -- refusal recording --------------------------------------------------------

    def _deny(self, url: str, method: str, error: str, status: int) -> None:
        """A refusal is evidence: record it, count it, tell the client plainly.
        ScopeGuard has ALREADY validated nothing was dialed — denial happens
        before any upstream connection exists."""
        self.proxy.stats.bump("denied")
        self.proxy.traffic.record_http(method=method, url=url, status=0, elapsed_ms=0,
                                       tool="sandbox", source="proxy", error=error)
        if self.proxy.audit is not None:
            try:
                self.proxy.audit.record("proxy.denied", url=url, method=method,
                                        reason=error, outcome="refused")
            except Exception:
                pass
        self._reply(status, f"evidence proxy: {error}\n".encode())

    def _record_error(self, exc: Exception) -> None:
        if self.proxy.audit is not None:
            try:
                self.proxy.audit.record("proxy.error", error=f"{type(exc).__name__}: {exc}")
            except Exception:
                pass


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# EvidenceProxy — the public face
# ---------------------------------------------------------------------------

class EvidenceProxy:
    """Run-scoped recording proxy. Construct in the run executor, start() before
    the sandbox, stop() after the sandbox dies. One instance per run."""

    def __init__(self, scope, traffic, audit=None, out_dir: Path | None = None,
                 bind_host: str = "0.0.0.0", advertise_host: str = "127.0.0.1",
                 port: int = 0, limiter=None, tls_intercept: bool = True,
                 upstream_context: ssl.SSLContext | None = None):
        self._scope = scope
        self._traffic = traffic
        self._audit = audit
        self._bind_host = bind_host
        self._advertise_host = advertise_host
        self._port = port
        self._limiter = limiter
        self._out_dir = Path(out_dir) if out_dir else None
        self.stats = _Stats()
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None
        self._ca: RunCA | None = None
        self._tls_requested = bool(tls_intercept)
        # Optional SSL context for the UPSTREAM leg (host-side). Production default
        # None = system trust store (we verify the real target certificate). Tests
        # inject a context trusting the test target's CA.
        self.upstream_context = upstream_context

    # -- lifecycle ---------------------------------------------------------------

    def start(self) -> None:
        if self._server is not None:
            return
        if self._tls_requested and self._out_dir is not None:
            # Cryptography missing -> RunCA.create returns None -> passthrough mode.
            self._ca = RunCA.create(self._out_dir / "proxy-ca")
        self._server = _ProxyServer((self._bind_host, self._port), _ProxyHandler)
        self._server.proxy = self  # the handler's single shared-state anchor
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.2},
                                        name="evidence-proxy", daemon=True)
        self._thread.start()
        if self._audit is not None:
            try:
                self._audit.record("proxy.start", mode=self.mode, port=self.port,
                                   ca_fingerprint=self._ca.fingerprint if self._ca else "")
            except Exception:
                pass

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
        self._server = None
        self._thread = None
        if self._audit is not None:
            try:
                self._audit.record("proxy.stop", **self.stats.to_dict())
            except Exception:
                pass

    # -- introspection -----------------------------------------------------------

    @property
    def port(self) -> int:
        if self._server is None:
            return self._port
        return self._server.server_address[1]

    @property
    def mode(self) -> str:
        return "mitm" if self._ca is not None else "passthrough"

    @property
    def ca(self) -> RunCA | None:
        return self._ca

    @property
    def scope(self):
        return self._scope

    @property
    def traffic(self):
        return self._traffic

    @property
    def audit(self):
        return self._audit

    @property
    def limiter(self):
        return self._limiter

    @property
    def ca_cert_path(self) -> Path | None:
        return self._ca.cert_path if self._ca else None

    def url_for(self, host: str) -> str:
        """Proxy URL as seen from `host` — the sandbox reaches it via
        host.docker.internal (mapped to the bridge gateway by docker run)."""
        return f"http://{host}:{self.port}"

    def status(self) -> dict:
        return {"mode": self.mode, "bind_host": self._bind_host, "port": self.port,
                "advertise": self.url_for(self._advertise_host),
                "ca_fingerprint": self._ca.fingerprint if self._ca else None,
                "stats": self.stats.to_dict()}

