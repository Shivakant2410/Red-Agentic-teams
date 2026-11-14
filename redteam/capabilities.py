"""Capability tags — content may only DO what its source may do (CaMeL-lite).

Paper ref: CaMeL (Debenedetti et al. 2025) kept 77% of AgentDojo utility provably
safe with capability-based dataflow: untrusted content carries its provenance as
CAPABILITIES, tools declare the capabilities they REQUIRE, and a policy engine —
not a model's judgment — decides. This module is that idea reduced to what this
stack needs: deterministic, offline, no LLM in the loop.

The invariant (W1/W6): an injection lives in the mismatch between what content
SAYS and what its source MAY do. A fetched page that says "approve the finding"
has no more authority than the page had before it said it. So:

  - content entering any agent context is TAGGED at the boundary with the
    capabilities its source legitimately holds (write-time, like memory.py's
    provenance — never reconstructed at read time);
  - actions/tools declare the capabilities they REQUIRE;
  - `check`/`enforce` are set comparisons, fail-closed.

Escalation scan: text whose imperative shape REQUESTS capabilities above its tag
is the agent-injection signature. On a hit the tag drops to the EMPTY set —
quarantine semantics, matching memory.py's row quarantine — and the flags name
what tripped, so the audit log says why, not just that.

Vocabulary (kept minimal on purpose; growing it is a policy decision, not a code
change): net:read (fetch), net:send (transmit context data out), exec (run
commands), write (mutate findings/memory/approvals), identity (touch credentials
and sessions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

NET_READ = "net:read"
NET_SEND = "net:send"
EXEC = "exec"
WRITE = "write"
IDENTITY = "identity"
ALL_CAPS = frozenset({NET_READ, NET_SEND, EXEC, WRITE, IDENTITY})

OPERATOR = "operator"              # the human brief, seeded credentials, RoE
SELF_DERIVED = "self_derived"      # our own verified pipeline output
TARGET_CONTROLLED = "target_controlled"  # anything that entered from the target

_SOURCE_CAPS = {
    OPERATOR: ALL_CAPS,
    SELF_DERIVED: frozenset({NET_READ, WRITE}),
    TARGET_CONTROLLED: frozenset({NET_READ}),
}

# memory.py provenance -> source class (rec 1 feeds rec 9: the store already
# decides trust at write time; this maps that decision into capability space).
_CAPS_FOR_PROVENANCE = {
    "derived": _SOURCE_CAPS[SELF_DERIVED],
    "imported": _SOURCE_CAPS[OPERATOR],
    "observed": _SOURCE_CAPS[TARGET_CONTROLLED],
}


def caps_for_source(source: str) -> frozenset:
    src = source.lower().strip()
    if src in _CAPS_FOR_PROVENANCE:          # memory.py provenance strings
        return _CAPS_FOR_PROVENANCE[src]
    if src not in _SOURCE_CAPS:
        raise ValueError(f"unknown source class {source!r}; "
                         f"known: {sorted(_SOURCE_CAPS)}")
    return _SOURCE_CAPS[src]


# -- escalation scan: text asking for authority its source does not hold -----------

_ESCALATION_PATTERNS: tuple[tuple[str, re.Pattern], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        ("ignore-previous", r"\bignore\s+(all\s+|any\s+)?(previous|prior|above)\b"),
        ("approve-finding", r"\bapprove\s+(the\s+)?(finding|finding[s]?|pending)\b"),
        ("call-tool", r"\bcall\s+the\s+[a-z_]+\s+tool\b"),
        ("send-to-url", r"\bsend\b.{0,60}\bto\s+https?://"),
        ("guard-disable", r"\bdisable\s+(the\s+)?(guard|scope|firewall|limit)s?\b"),
        ("credential-send", r"\b(credentials|token[s]?|secret[s]?)\b.{0,40}\b(send|post|forward|exfiltrat)\w*\b"),
        ("memory-plant", r"\b(remember|note)\s+(that|this|for\s+(future|later))\b"),
        ("role-forgery", r"(?im)^\s*system\s*:"),
        ("authority-token", r"\bsupervisor\s+token\b"),
        ("exec-ask", r"\b(run|execute)\s+(the\s+)?(command|shell|cmd)\b"),
    )
)


@dataclass(frozen=True)
class Tagged:
    text: str
    source: str
    caps: frozenset = frozenset()
    flags: tuple = field(default=())

    @property
    def escalated(self) -> bool:
        return bool(self.flags)


def tag(text: str, source: str) -> Tagged:
    """Tag content at the boundary. Escalation-shaped text loses ALL caps —
    except when the source already holds everything (OPERATOR): the operator IS
    the authority, and a human brief saying "run the command" is legitimate
    delegation, not self-escalation. The flags record why, the text itself is
    never rewritten here (rewriting is the quarantine layer's job, swarmguard.py)."""
    caps = caps_for_source(source)
    flags = tuple(name for name, rx in _ESCALATION_PATTERNS if rx.search(text or ""))
    if flags and caps != ALL_CAPS:
        caps = frozenset()
    return Tagged(text=text or "", source=source.lower(), caps=caps, flags=flags)


# -- the policy engine ---------------------------------------------------------------

@dataclass(frozen=True)
class Action:
    """Something the stack can be asked to do, with the capabilities it requires."""
    name: str
    required: frozenset


# Standard actions for this stack's sensitive verbs (tools declare these at the
# dispatch boundary; the names mirror the tool registry, not the model's prose).
ACTION_HTTP_PROBE = Action("http_probe", frozenset({NET_READ}))
ACTION_VERIFY = Action("verify_vulnerability", frozenset({NET_READ, WRITE}))
ACTION_RECORD_FINDING = Action("record_finding", frozenset({WRITE}))
ACTION_CONFIRM = Action("confirm_finding", frozenset({WRITE}))
ACTION_KALI_EXEC = Action("kali_exec", frozenset({EXEC}))
ACTION_SEND_OUT = Action("send_context_out", frozenset({NET_SEND}))
ACTION_USE_CREDENTIALS = Action("use_credentials", frozenset({IDENTITY}))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    action: str
    missing: frozenset = frozenset()

    def reason(self) -> str:
        if self.allowed:
            return f"allowed: {self.action}"
        return (f"denied: {self.action} requires "
                f"{sorted(self.missing)} which content from this source "
                f"does not hold")


def check(tagged: Tagged, action: Action) -> Decision:
    missing = frozenset(action.required) - frozenset(tagged.caps)
    return Decision(allowed=not missing, action=action.name, missing=missing)


class CapabilityDenied(PermissionError):
    """Fail-closed enforcement error; carries the Decision for the audit log."""


def enforce(tagged: Tagged, action: Action) -> Decision:
    d = check(tagged, action)
    if not d.allowed:
        preview = (tagged.text or "")[:80].replace("\n", " ")
        raise CapabilityDenied(f"{d.reason()} | content: {preview!r}")
    return d


# -- reporting ------------------------------------------------------------------------

def policy_report(pairs: list[tuple[Tagged, Action]]) -> str:
    """Markdown block for a cell card: every (content, action) pair and its verdict."""
    lines = ["| content source | action | verdict |", "| --- | --- | --- |"]
    for tagged, action in pairs:
        d = check(tagged, action)
        lines.append(f"| {tagged.source} | {action.name} | "
                     f"{'allow' if d.allowed else 'DENY'} |")
    return "\n".join(lines)
