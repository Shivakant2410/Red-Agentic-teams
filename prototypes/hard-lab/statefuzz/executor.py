"""Real-HTTP executor with budget, STOP kill-file, traffic recording, and a
last-byte-synchronised race primitive (Kettle tradecraft over HTTP/1.1).

Every wire exchange is appended to traffic.jsonl so any finding ships with a
replayable transcript. The race primitive holds back the final body byte of N
pre-negotiated connections, releases them inside one event loop turn, and
therefore lands the N writes inside the target's check-then-act window.
"""
import json
import os
import socket
import threading
import time
import urllib.parse

import requests


class StopFuzz(Exception):
    """Raised when the STOP kill file appears or the budget is exhausted."""


class Principal:
    """One authenticated identity with its own cookie/token jar."""

    def __init__(self, name, token=None):
        self.name = name
        self.token = token
        self.http = requests.Session()

    @property
    def auth_headers(self):
        return {"Authorization": "Bearer " + self.token} if self.token else {}


class Exchange(dict):
    pass


class Executor:
    def __init__(self, base_url, traffic_path, stop_file=None, budget=400):
        self.base = base_url.rstrip("/")
        p = urllib.parse.urlparse(self.base)
        self.host, self.port = p.hostname, p.port or 80
        self.traffic_path = traffic_path
        self.stop_file = stop_file or os.path.join(os.getcwd(), "STOP")
        self.budget = budget
        self.count = 0
        self._seq = 0
        self._tlock = threading.Lock()
        self.principals = {}          # name -> Principal (filled by the model)

    def principals_get(self, name):
        return self.principals[name]

    # ----------------------------------------------------------------- ops --
    def check_stop(self):
        if os.path.exists(self.stop_file):
            raise StopFuzz("STOP kill file present: %s" % self.stop_file)
        if self.count >= self.budget:
            raise StopFuzz("request budget exhausted (%d)" % self.budget)

    def _record(self, ex):
        with self._tlock:
            self._seq += 1
            ex["seq"] = self._seq
            with open(self.traffic_path, "a") as fh:
                fh.write(json.dumps(ex) + "\n")

    def request(self, principal, method, path, body=None, headers=None,
                phase="", tag=""):
        """One ordinary HTTP exchange. Returns an Exchange dict."""
        self.check_stop()
        self.count += 1
        url = self.base + path
        h = dict(principal.auth_headers)
        h.update(headers or {})
        t0 = time.time()
        try:
            r = principal.http.request(method, url, json=body, headers=h, timeout=5)
            status, resp_body = r.status_code, _safe_json(r.text)
            resp_headers = dict(list(r.headers.items())[:8])
        except requests.RequestException as e:
            status, resp_body = 0, {"transport_error": str(e)[:200]}
            resp_headers = {}
        ex = Exchange(principal=principal.name, method=method, path=path,
                      req_body=body, req_headers={k: v for k, v in h.items()
                                                  if k != "Authorization"},
                      has_auth=bool(principal.token), status=status,
                      resp_body=resp_body, resp_headers=resp_headers,
                      ts=time.time(), phase=phase,
                      tag=tag, elapsed_ms=round((time.time() - t0) * 1000, 1))
        self._record(ex)
        return ex

    # ---------------------------------------------------------------- race --
    def race(self, principal, method, path, body, n=8, phase="", tag="INTERRUPT"):
        """Last-byte sync: N sockets pre-negotiated, final byte released after
        a barrier, so all N requests enter the server within ~microseconds.
        Returns the N parsed responses (and records them under one tag)."""
        self.check_stop()
        self.count += n
        payload = json.dumps(body).encode()
        head = ("%s %s HTTP/1.1\r\nHost: %s:%d\r\n%sContent-Type: "
                "application/json\r\nContent-Length: %d\r\nConnection: close"
                "\r\n\r\n" % (method, path, self.host, self.port,
                              ("Authorization: Bearer %s\r\n" % principal.token)
                              if principal.token else "", len(payload))).encode()
        first, last = head + payload[:-1], payload[-1:]

        socks = []
        try:
            for _ in range(n):
                s = socket.create_connection((self.host, self.port), timeout=5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.sendall(first)
                socks.append(s)
            barrier = threading.Barrier(1)          # single releaser
            barrier.wait()                          # desync floor ~= 0 here;
            for s in socks:                         # release all final bytes
                s.sendall(last)                     # in one loop turn

            results = []
            for s in socks:
                raw = b""
                s.settimeout(5)
                try:
                    while True:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        raw += chunk
                except socket.timeout:
                    pass
                status, resp = _parse_http(raw)
                results.append({"status": status, "resp_body": resp})
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass

        ex = Exchange(principal=principal.name, method=method, path=path,
                      req_body=body, race_n=n, status=None,
                      responses=results, ts=time.time(), phase=phase,
                      tag=tag, last_byte_sync=True)
        self._record(ex)
        return results

    def race_multi(self, principals, method, path, body, phase="",
                   tag="INTERRUPT"):
        """Last-byte sync across DIFFERENT principals (one socket each): all N
        authenticated requests enter the server inside one event-loop turn.
        Needed for quota-style races where a per-account guard forces every
        racer onto its own identity. Additive; behaviour of race() unchanged."""
        n = len(principals)
        self.check_stop()
        self.count += n
        payload = json.dumps(body).encode()
        first, last = [], payload[-1:]
        socks = []
        try:
            for p in principals:
                head = ("%s %s HTTP/1.1\r\nHost: %s:%d\r\n%sContent-Type: "
                        "application/json\r\nContent-Length: %d\r\n"
                        "Connection: close\r\n\r\n"
                        % (method, path, self.host, self.port,
                           ("Authorization: Bearer %s\r\n" % p.token)
                           if p.token else "", len(payload))).encode()
                s = socket.create_connection((self.host, self.port), timeout=5)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.sendall(head + payload[:-1])
                socks.append(s)
            threading.Barrier(1).wait()
            for s in socks:
                s.sendall(last)
            results = []
            for s in socks:
                raw = b""
                s.settimeout(5)
                try:
                    while True:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        raw += chunk
                except socket.timeout:
                    pass
                status, resp = _parse_http(raw)
                results.append({"status": status, "resp_body": resp})
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
        ex = Exchange(principal=",".join(p.name for p in principals),
                      method=method, path=path, req_body=body, race_n=n,
                      status=None, responses=results, ts=time.time(),
                      phase=phase, tag=tag, last_byte_sync=True,
                      multi_principal=True)
        self._record(ex)
        return results


def _safe_json(text):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {"raw": str(text)[:300]}


def _parse_http(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ")[1])
    except (IndexError, ValueError):
        status = 0
    return status, _safe_json(body.decode("utf-8", "replace"))
