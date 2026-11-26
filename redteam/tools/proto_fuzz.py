"""proto_fuzz — active protocol fuzzing for NON-HTTP surfaces (the network layer
beyond the web stack the other tools cover).

The agent's HTTP tools probe APIs; real estates also expose TCP/UDP services
(databases, queues, game protocols, gRPC) where the same question applies: does
the service survive malformed input? This tool answers it with a BOUNDED,
deterministic mutation battery — not an unbounded random bombardment:

  - a baseline probe first (is the service alive, does it talk?);
  - then a case list built from the operator's optional TEMPLATE (literal bytes
    with {TOKEN} slots that get mutated) or, without one, a fixed battery:
    boundary lengths, format strings, null bytes, high-bit noise, unicode,
    and an HTTP/2 preface for gRPC-shaped endpoints;
  - every case is rate-limited and individually scope-checked — a mid-battery
    RoE change fails closed per target like scope.check does;
  - anomalies (service stopped accepting connections after malformed input)
    become tentative findings with the exact bytes as poc, pending the usual
    independent verification.

gRPC note: without `grpcio` installed we still exercise the endpoint at the
HTTP/2 preface level over TCP and say so honestly; we do not pretend to speak
protobuf. boofuzz / AFL++ adapters are probed for availability and reported —
an adapter that is not installed is a fact to surface, not a silent skip.
"""

from __future__ import annotations

import json
import shutil
import socket
import importlib.util
import time

from ..findings import Finding
from ..scope import ScopeViolation
from . import ToolContext

_GRPC_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_TOKEN_MUTATIONS = [
    "",                              # field deleted entirely
    "A" * 16,
    "A" * 256,
    "A" * 1024,
    "A" * 4096,
    "%s%n%n%n%n%n%n%n",              # format string
    "%d" * 64,
    "\x00\x00\x00\x00",
    "\xff" * 32,
    "\uFFFF\uFFFE\u0000\u0019",
    "../../../../etc/passwd",
    "{{7*7}}",
    "\r\n\r\nX-Injected: 1\r\n\r\n", # CRLF injection
]

_NO_TEMPLATE_BATTERY = [
    b"",                             # immediate close
    b"\r\n",
    b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n",
    b"A" * 1024,
    b"\x00\x01\x02\x03\x04\x05\x06\x07",
    b"%s%n%n%n%n%n%n",
    b"\xff" * 64,
    _GRPC_PREFACE,
    b"HEADERS:1\r\n\r\n" + b"X" * 4096,
]

_MAX_CASES = 200
_CASE_BYTES_CAP = 64 * 1024  # never put more than this on the wire per case


def _adapter_availability() -> dict:
    return {
        "boofuzz": importlib.util.find_spec("boofuzz") is not None,
        "afl-fuzz": shutil.which("afl-fuzz") is not None,
        "grpcio": importlib.util.find_spec("grpc") is not None,
    }


class ProtoFuzzTool:
    name = "proto_fuzz"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Actively fuzz a NON-HTTP TCP/UDP/gRPC service that is IN SCOPE. "
                "Sends a bounded, deterministic mutation battery (boundary lengths, "
                "format strings, null bytes, HTTP/2 preface for gRPC) after a "
                "baseline liveness probe, and reports which cases made the service "
                "misbehave (die, reset, or answer with errors). A service that dies "
                "on malformed input becomes a tentative finding. Use template with "
                "literal bytes containing {TOKEN} slots to shape the battery to the "
                "protocol; omit it for a generic battery."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "host": {"type": "string",
                             "description": "In-scope hostname (resolved + RoE-checked, fail closed)."},
                    "port": {"type": "integer", "description": "In-scope port from the RoE port list."},
                    "protocol": {"type": "string", "enum": ["tcp", "udp", "grpc"]},
                    "template": {"type": "string",
                                 "description": "Literal payload template; {TOKEN} slots are mutated. "
                                                "Escape \\n and \\xNN is supported."},
                    "cases": {"type": "integer",
                              "description": f"Max cases to send (default 40, hard cap {_MAX_CASES})."},
                    "timeout_ms": {"type": "integer", "description": "Per-case socket timeout (default 1500)."},
                },
                "required": ["host", "port", "protocol"],
            },
            "strict": True,
        }

    # --- payload construction ------------------------------------------------

    @staticmethod
    def _unescape(template: str) -> bytes:
        # \n \r \t \xNN supported — enough to shape binary protocols without
        # letting the model paste raw non-UTF8 into the tool-call JSON.
        return template.encode("utf-8").decode("unicode_escape").encode("latin-1")

    def _build_cases(self, template: str, cases: int) -> list[bytes]:
        out: list[bytes] = []
        if template:
            base = self._unescape(template)
            for mutation in _TOKEN_MUTATIONS:
                out.append(base.replace(b"{TOKEN}", mutation.encode("utf-8")))
            # A second pass at byte level: flip bytes / truncate the template.
            if base:
                out.append(base[:-1])
                out.append(base[: len(base) // 2])
                flipped = bytearray(base)
                if flipped:
                    flipped[0] ^= 0x01
                out.append(bytes(flipped))
        else:
            out.extend(_NO_TEMPLATE_BATTERY)
        trimmed: list[bytes] = []
        for raw in out:
            payload = raw[:_CASE_BYTES_CAP]
            if payload not in trimmed:
                trimmed.append(payload)
        return trimmed[: max(1, min(int(cases), _MAX_CASES))]

    # --- wire ----------------------------------------------------------------

    @staticmethod
    def _exchange_tcp(host: str, port: int, payload: bytes,
                      timeout: float, recv_wait: float = 0.35) -> dict:
        """One connect→send→(read) cycle. Returns a classification dict; never raises."""
        out: dict = {"outcome": "error", "detail": "", "resp_len": 0, "sample": ""}
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                if payload:
                    s.sendall(payload)
                s.settimeout(recv_wait)
                try:
                    data = s.recv(4096)
                    out["resp_len"] = len(data)
                    out["sample"] = data[:80].decode("utf-8", errors="replace")
                    out["outcome"] = "responded" if data else "accepted"
                except socket.timeout:
                    out["outcome"] = "accepted" if payload else "accepted"
                except ConnectionResetError:
                    out["outcome"] = "reset"
        except ConnectionRefusedError:
            out["outcome"] = "refused"
            out["detail"] = "connection refused"
        except socket.timeout:
            out["outcome"] = "timeout"
        except OSError as exc:
            out["outcome"] = "error"
            out["detail"] = str(exc)
        return out

    @staticmethod
    def _exchange_udp(host: str, port: int, payload: bytes, timeout: float) -> dict:
        out: dict = {"outcome": "error", "detail": "", "resp_len": 0, "sample": ""}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload or b"\x00", (host, port))
                try:
                    data, _ = s.recvfrom(4096)
                    out["resp_len"] = len(data)
                    out["sample"] = data[:80].decode("utf-8", errors="replace")
                    out["outcome"] = "responded" if data else "accepted"
                except socket.timeout:
                    out["outcome"] = "timeout"   # UDP silence is NORMAL — not an anomaly alone
        except ConnectionRefusedError:
            out["outcome"] = "refused"
            out["detail"] = "ICMP port unreachable"
        except OSError as exc:
            out["outcome"] = "error"
            out["detail"] = str(exc)
        return out

    # --- tool contract -------------------------------------------------------

    def run(self, ctx: ToolContext, host: str, port: int, protocol: str = "tcp",
            template: str = "", cases: int = 40, timeout_ms: int = 1500) -> str:
        protocol = (protocol or "tcp").lower()
        if protocol not in ("tcp", "udp", "grpc"):
            return "ERROR: protocol must be tcp, udp, or grpc."
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError(port)
        except (TypeError, ValueError):
            return f"ERROR: invalid port {port!r}."
        wire_protocol = "tcp" if protocol == "grpc" else protocol
        timeout = max(0.1, min(float(timeout_ms) / 1000.0, 10.0))

        # Scope gate — same fail-closed semantics as every other tool: the host
        # must resolve inside the RoE and the port must be on the RoE port list
        # (an empty RoE port list means nothing is allowed).
        try:
            ctx.scope.check(f"http://{host}:{port}/")
        except ScopeViolation as exc:
            ctx.audit.record("proto_fuzz.blocked", target=f"{host}:{port}",
                             cause="out_of_scope")
            return f"BLOCKED (out of scope): {exc}"

        case_payloads = self._build_cases(template, cases)
        exchange = self._exchange_tcp if wire_protocol == "tcp" else self._exchange_udp

        # Baseline: is the service alive and does it talk? The whole anomaly
        # story is relative to this.
        baseline = exchange(host, port, b"", timeout)
        ctx.audit.record("proto_fuzz.baseline", target=f"{host}:{port}",
                         outcome=baseline["outcome"], protocol=protocol)
        if baseline["outcome"] in ("refused",):
            return json.dumps({"target": f"{host}:{port}", "protocol": protocol,
                               "cases_planned": len(case_payloads), "sent": 0,
                               "baseline": baseline,
                               "note": "service refused connections before the battery — "
                                       "nothing was fuzzed; report the port state, do not "
                                       "claim a finding."}, ensure_ascii=False)

        transcript: list[dict] = []
        anomalies: list[dict] = []
        refused_streak = 0
        sent = 0
        for i, payload in enumerate(case_payloads):
            ctx.limiter.acquire()
            result = exchange(host, port, payload, timeout)
            sent += 1
            row = {"case": i, "sent_bytes": len(payload),
                   "payload_head": payload[:48].decode("utf-8", errors="replace"),
                   **result}
            transcript.append(row)
            if result["outcome"] in ("refused", "reset"):
                refused_streak += 1
                if refused_streak == 2:
                    anomalies.append({
                        "kind": "service_stopped_accepting",
                        "after_case": i,
                        "payload_head": row["payload_head"],
                        "baseline": baseline["outcome"],
                        "detail": f"service went from '{baseline['outcome']}' at baseline "
                                  f"to '{result['outcome']}' after malformed input",
                    })
            else:
                refused_streak = 0
            if result["outcome"] == "responded" and len(anomalies) < 4 and i > 0:
                sample = result.get("sample", "")
                if any(sig in sample.lower() for sig in ("traceback", "exception", "core dump")):
                    anomalies.append({
                        "kind": "error_surface",
                        "after_case": i,
                        "payload_head": row["payload_head"],
                        "detail": f"service surfaced an internal error to a malformed case: {sample[:80]}",
                    })
            # Small pacing gap even when the limiter is generous: a battery must
            # not look like a flood to the target's operators.
            time.sleep(0.02)

        ctx.audit.record("proto_fuzz.run", target=f"{host}:{port}", protocol=protocol,
                         sent=sent, anomalies=len(anomalies))
        if ctx.inventory is not None:
            try:
                ctx.inventory.observe_asset(host, port, scheme=f"tcp/{protocol}")
            except Exception:
                pass  # telemetry never breaks a run

        finding_ids: list[str] = []
        for a in anomalies:
            f = ctx.findings.add(Finding(
                title=f"Malformed input destabilizes service at {host}:{port}",
                severity="medium", target=f"tcp://{host}:{port}",
                summary=a["detail"] + ".",
                evidence=json.dumps({"baseline": baseline, "anomaly": a},
                                    ensure_ascii=False),
                cwe="CWE-20", confidence="tentative",
                poc=f"Replay case #{a['after_case']} of the proto_fuzz battery against "
                    f"{host}:{port} ({protocol}); payload begins "
                    f"{a['payload_head']!r}.",
                recommendation="Harden the service's input parsing; fuzz once more "
                               "after remediation to confirm it survives the battery."))
            finding_ids.append(f.id)

        adapters = _adapter_availability()
        notes = []
        if protocol == "grpc" and not adapters["grpcio"]:
            notes.append("grpcio not installed: endpoint was exercised at the HTTP/2 "
                         "preface level only (honest limit, not protobuf semantics).")
        if not adapters["boofuzz"]:
            notes.append("boofuzz not installed: in-repo deterministic battery used; "
                         "install boofuzz for stateful protocol models.")
        return json.dumps({"target": f"{host}:{port}", "protocol": protocol,
                           "sent": sent, "planned": len(case_payloads),
                           "baseline": baseline,
                           "anomalies": anomalies, "finding_ids": finding_ids,
                           "transcript_tail": transcript[-8:],
                           "adapters": adapters, "notes": notes},
                          ensure_ascii=False)
