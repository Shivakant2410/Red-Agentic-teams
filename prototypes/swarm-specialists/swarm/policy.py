"""PolicyGuard — the platform-shaped scope + approval gate (G5, M4).

The prototype's scope check used to be a bare bool function with one call
site; G5 asks for a real gate: per-run target admission AND a per-action
approval gate on write mutants, with an auditable decision record.

Research basis (RESEARCH-M4.md R2/R3, visited 2026-11):
  - CaMeL (arXiv:2503.18813): security policies enforced at tool-call
    boundaries from a system layer, even when the model is compromised
    (AgentDojo: 77% of tasks WITH provable security vs 84% undefended —
    the published price of provable denial).
  - XBOW's own architecture note: "We ensure that every agent action is
    checked before execution"; "We give agents only the tools they need".
  - Platform twin: redteam/scope.py (fail-closed ScopeGuard.check(),
    allowlist + resolved-IP check, ScopeViolation).
  - The project charter (docs/competitor-landscape.md): "deterministic
    enforcement independent of the model".

Design:
  - TWO checks. check_target() admits the engagement (fail-closed:
    loopback / TEST-NET-1 only — same rule the registry always had).
    check_action() gates every single wire action at the executor
    chokepoint: reads are always allowed; write mutants need the
    engagement's approval mode —
        approvals="lab"  auto-approve inside the audited scope (labs),
        approvals="none" deny every write mutant (the refusal mode).
    Any UNKNOWN approval mode is a construction error (fail-closed).
  - Every decision (allow AND deny) is appended to policy_audit.jsonl so
    an engagement ships with a replayable record of who was allowed to
    do what.
  - Policy reads NOTHING from memory: the gate cannot be talked into
    anything by prior runs' content.
"""
import ipaddress
import json
import os
import time
import urllib.parse

READ_METHODS = ("GET", "HEAD", "OPTIONS")


class Decision(dict):
    """One policy verdict: {allow, rule, reason}."""

    @property
    def allow(self):
        return bool(self.get("allow"))


def _dec(allow, rule, reason=""):
    return Decision(allow=allow, rule=rule, reason=reason)


def host_allowed(base_url):
    """The registry's original scope rule, as a function: loopback or
    TEST-NET-1 (192.0.2.0/24), nothing else. Kept byte-compatible with
    registry_tool._scope_ok."""
    host = urllib.parse.urlparse(base_url).hostname or ""
    if host in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host) in \
            ipaddress.ip_network("192.0.2.0/24")
    except ValueError:
        return False


class PolicyGuard:
    """Protocol served by every policy. (Seam: the platform ScopeGuard
    implements the same two checks; see redteam/scope.py.)"""

    name = "policy"

    def check_target(self, base_url):
        raise NotImplementedError

    def check_action(self, principal, method, path):
        raise NotImplementedError


class LabPolicy(PolicyGuard):
    """Fail-closed lab policy with audited decisions."""

    name = "lab-policy"

    def __init__(self, approvals="lab", audit_path=None):
        if approvals not in ("lab", "none"):
            # fail closed at construction: an unknown mode denies nothing
            # silently, it refuses to exist
            raise ValueError("approvals must be 'lab' or 'none', got %r"
                             % (approvals,))
        self.approvals = approvals
        self.audit_path = audit_path
        self.decisions = []

    # ------------------------------------------------------------- checks --
    def check_target(self, base_url):
        ok = host_allowed(base_url)
        d = _dec(ok, "scope:loopback-testnet1" if ok else "scope:refused",
                 "" if ok else "%s is not loopback or TEST-NET-1" % base_url)
        return self._audit(d, principal="-", method="ENGAGE", path=base_url)

    def check_action(self, principal, method, path):
        m = (method or "").upper()
        if m in READ_METHODS:
            return self._audit(_dec(True, "read"), principal, m, path)
        if self.approvals == "lab":
            return self._audit(_dec(True, "approval:lab-auto"),
                               principal, m, path)
        return self._audit(
            _dec(False, "approval:none",
                 "write mutant denied (approvals=none)"),
            principal, m, path)

    # -------------------------------------------------------------- audit --
    def _audit(self, decision, principal, method, path):
        entry = {"ts": time.time(), "principal": principal,
                 "method": method, "path": path,
                 "allow": bool(decision["allow"]),
                 "rule": decision["rule"], "reason": decision["reason"]}
        self.decisions.append(entry)
        if self.audit_path:
            os.makedirs(os.path.dirname(self.audit_path) or ".",
                        exist_ok=True)
            with open(self.audit_path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        return decision

    # ------------------------------------------------------------- report --
    def stats(self):
        denied = [d for d in self.decisions if not d["allow"]]
        return {"policy": self.name, "approvals": self.approvals,
                "decisions": len(self.decisions), "denied": len(denied),
                "denied_sample": denied[:8]}
