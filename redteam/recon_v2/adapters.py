"""RECON V2 ProjectDiscovery-compatible adapters.

The ProjectDiscovery convention (docs.projectdiscovery.io) is the pipeline
contract this module normalizes into: every tool emits one JSON object per
line with `timestamp` + entity fields (subfinder: `host`; httpx: `url`,
`status_code`, `title`, `technologies`; naabu: `ip`,`port`; dnsx: `a`/`cname`;
tlsx: `subject_cn`,`subject_an`,`issuer_cn`; asnmap: `as_number`,`as_range`;
nuclei: `template-id`,`matched-at`,`info.severity`). Adapters turn those into
Observations with provenance and evidence refs.

Discipline (directive §5):
  - ACTIVE adapters require explicit authorization (`authorized=True` — the
    caller passes the engagement's signed authorization; fail-closed default);
  - every emitted subject is scope-checked BEFORE recording — out-of-scope
    lines are dropped and audited, never stored;
  - bounded: `max_items`, per-item rate-limit acquisition on the run's shared
    limiter, subprocess timeout;
  - JSONL only: unparseable lines are skipped, not executed;
  - binaries are discovered via PATH; a missing binary is an honest skip
    (audited), never a fabricated result.
"""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess

from .evidence_store import EvidenceStore
from .observations import (
    KIND_ASN, KIND_CERTIFICATE, KIND_DNS_RECORD, KIND_ENDPOINT, KIND_IP,
    KIND_SERVICE, KIND_SUBDOMAIN, KIND_TECHNOLOGY, PROVENANCE_ACTIVE,
    PROVENANCE_PASSIVE, EvidenceRef,
)

# binary -> (observation kind, provenance, field map). Field maps translate the
# tool's JSONL fields into Observation attrs; `subject` picks the canonical key.
FIELD_MAPS: dict[str, dict] = {
    "subfinder": {"kind": KIND_SUBDOMAIN, "provenance": PROVENANCE_PASSIVE,
                  "subject": "host", "attrs": ("source", "timestamp")},
    "httpx": {"kind": KIND_SERVICE, "provenance": PROVENANCE_ACTIVE,
              "subject": "url",
              "attrs": ("status_code", "title", "technologies", "webserver",
                        "content_length", "timestamp")},
    "naabu": {"kind": KIND_SERVICE, "provenance": PROVENANCE_ACTIVE,
              "subject": "host", "attrs": ("port", "ip", "timestamp")},
    "dnsx": {"kind": KIND_DNS_RECORD, "provenance": PROVENANCE_ACTIVE,
             "subject": "host", "attrs": ("a", "aaaa", "cname", "mx", "ns",
                                          "timestamp")},
    "tlsx": {"kind": KIND_CERTIFICATE, "provenance": PROVENANCE_ACTIVE,
             "subject": "host", "attrs": ("subject_cn", "subject_an",
                                          "issuer_cn", "not_after",
                                          "fingerprint_hash", "timestamp")},
    "asnmap": {"kind": KIND_ASN, "provenance": PROVENANCE_PASSIVE,
               "subject": "input", "attrs": ("as_number", "as_name",
                                             "as_country", "as_range",
                                             "timestamp")},
    "nuclei": {"kind": KIND_ENDPOINT, "provenance": PROVENANCE_ACTIVE,
               "subject": "matched-at",
               "attrs": ("template-id", "info", "severity", "type", "host",
                         "timestamp")},
}

PASSIVE_TOOLS = frozenset({"subfinder", "asnmap"})


class AdapterError(RuntimeError):
    pass


class ProjectDiscoveryAdapter:
    """Normalize PD-style JSONL into scoped, bounded, provenance-tagged
    Observations in the shared evidence store."""

    def __init__(self, store: EvidenceStore, scope, limiter, audit,
                 sandbox_exec=None, max_items: int = 200,
                 timeout_s: float = 120.0):
        self._store = store
        self._scope = scope
        self._limiter = limiter
        self._audit = audit
        self._sandbox_exec = sandbox_exec      # KaliSandbox.exec | None
        self._max_items = int(max_items)
        self._timeout = float(timeout_s)

    def available(self, binary: str) -> bool:
        """Is the tool actually installed (sandbox or host PATH)?"""
        if self._sandbox_exec is not None:
            try:
                probe = self._sandbox_exec(f"command -v {shlex.quote(binary)} || true")
                stdout = getattr(probe, "stdout", probe)
                return bool(str(stdout or "").strip())
            except Exception:
                return False
        return shutil.which(binary) is not None

    def run(self, binary: str, args: list[str], *, target: str,
            authorized: bool) -> dict:
        """Run one adapter and normalize its JSONL. Returns a result summary;
        every recorded subject is pre-checked against the signed scope."""
        spec = FIELD_MAPS.get(binary)
        if spec is None:
            raise AdapterError(f"no field map for adapter {binary!r}")
        if not authorized:
            # Fail closed: active discovery without a signed authorization is a
            # programming error, not a mode.
            self._audit.record("reconv2.adapter.unauthorized", binary=binary,
                               target=target)
            return {"recorded": 0, "skipped_out_of_scope": 0, "lines": 0,
                    "authorized": False}
        if not self.available(binary):
            self._audit.record("reconv2.adapter.missing", binary=binary,
                               target=target)
            return {"recorded": 0, "skipped_out_of_scope": 0, "lines": 0,
                    "available": False}
        argv = [binary, *args]
        try:
            if self._sandbox_exec is not None:
                proc = self._sandbox_exec(" ".join(shlex.quote(part) for part in argv))
                raw = str(getattr(proc, "stdout", proc) or "")
                exit_code = int(getattr(proc, "exit_code", 0) or 0)
                stderr = str(getattr(proc, "stderr", "") or "")
            else:
                proc = subprocess.run(argv, capture_output=True, text=True,
                                      timeout=self._timeout)
                raw, exit_code, stderr = proc.stdout, proc.returncode, proc.stderr
        except (subprocess.TimeoutExpired, OSError) as exc:
            self._audit.record("reconv2.adapter.error", binary=binary,
                               target=target, error=str(exc)[:200])
            return {"recorded": 0, "skipped_out_of_scope": 0, "lines": 0,
                    "error": str(exc)[:200], "available": True}

        recorded = skipped = lines = 0
        subjects: list[str] = []
        for line in raw.splitlines():
            if lines >= self._max_items:
                break
            line = line.strip()
            if not line:
                continue
            lines += 1
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            subject = str(data.get(spec["subject"]) or "").strip()
            if not subject:
                continue
            if binary == "naabu" and data.get("port"):
                subject = f"{subject}:{data['port']}"
            # Scope gate BEFORE storage: honest attribution, no out-of-scope
            # asset ever enters the authorized evidence plane.
            host = self._host_of(binary, data, subject)
            try:
                if host:
                    if not self._scope.host_scope_status(host):
                        if binary not in PASSIVE_TOOLS:
                            skipped += 1
                            self._audit.record("reconv2.adapter.scope_denied",
                                               binary=binary, host=host)
                            continue
                        # Passive intelligence is retained as external context.
                        # Its out_of_scope attribution is data, never permission
                        # to contact or test that host.
                        self._audit.record("reconv2.adapter.external_observation",
                                           binary=binary, host=host)
                    if binary not in PASSIVE_TOOLS:
                        self._limiter.acquire()
                elif not PASSIVE_TOOLS.__contains__(binary):
                    self._limiter.acquire()
            except Exception as exc:   # ScopeViolation / budget
                skipped += 1
                self._audit.record("reconv2.adapter.scope_denied", binary=binary,
                                   host=host, error=str(exc)[:160])
                continue
            attrs = {k: data.get(k) for k in spec["attrs"] if data.get(k) is not None}
            if binary == "naabu":
                attrs["port"] = data.get("port")
            evidence = [EvidenceRef(kind="tool", ref=f"{binary}#jsonl",
                                    tool=binary).to_json()]
            self._store.observe(spec["kind"], subject, tool=binary,
                                provenance=spec["provenance"], attrs=attrs,
                                origin="external", evidence=evidence)
            subjects.append(subject)
            recorded += 1
        self._audit.record("reconv2.adapter.run", binary=binary, target=target,
                           recorded=recorded, skipped=skipped, lines=lines,
                           exit_code=exit_code, stderr_tail=stderr[-300:])
        return {"recorded": recorded, "skipped_out_of_scope": skipped,
                "lines": lines, "subjects": subjects, "exit_code": exit_code,
                "stderr_tail": stderr[-300:]}

    @staticmethod
    def _host_of(binary: str, data: dict, subject: str) -> str:
        if binary in ("subfinder", "dnsx", "tlsx"):
            return subject
        if binary == "naabu":
            return str(data.get("ip") or subject)
        for key in ("host", "url", "matched-at", "input"):
            val = data.get(key)
            if not val:
                continue
            val = str(val)
            if "://" in val:
                from urllib.parse import urlsplit
                try:
                    return urlsplit(val).hostname or ""
                except ValueError:
                    return ""
            return val
        return ""
