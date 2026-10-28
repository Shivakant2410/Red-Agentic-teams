"""The KILL CHAIN — an adversary's stage model, replacing the vulnerability checklist.

Our old attack tree asked "which vuln class is untested on this endpoint?" — a scanner's
question, and the reason the system kept behaving like a scanner. This asks the operator's
question instead: **given what I hold and where the objective is, which tactic advances me?**

Stages follow the ATT&CK-style progression. Crucially the recommendation is driven by the
ACCESS GRAPH (what we hold) and the OBJECTIVE (where we're going), not by coverage of a
vuln taxonomy. A SQL injection matters here only insofar as it yields a credential, a
session, or a host — otherwise it's a side note to write up, not a win.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .access import CREDENTIAL, HOST, PRINCIPAL

RECON = "reconnaissance"
INITIAL_ACCESS = "initial-access"
EXECUTION = "execution"
CREDENTIAL_ACCESS = "credential-access"
DISCOVERY = "discovery"
PRIVILEGE_ESCALATION = "privilege-escalation"
LATERAL_MOVEMENT = "lateral-movement"
COLLECTION = "collection"
EXFILTRATION = "exfiltration"
PERSISTENCE = "persistence"
DEFENSE_EVASION = "defense-evasion"

NOT_STARTED, IN_PROGRESS, ACHIEVED = "not_started", "in_progress", "achieved"

# Ordered stages with what each is FOR, in objective terms.
STAGES: dict[str, str] = {
    RECON: "Map the organization's reachable surface: hosts, services, apps, identities.",
    INITIAL_ACCESS: "Obtain your first foothold — any authenticated principal, session, or "
                    "host you can act from. Without this nothing else is possible.",
    EXECUTION: "Run code or commands in the target's context.",
    CREDENTIAL_ACCESS: "Harvest secrets — tokens, passwords, keys — that authenticate you "
                       "as another principal. This is usually what unlocks the chain.",
    DISCOVERY: "From your foothold, enumerate what you can now see that you could not see "
               "from outside: internal hosts, data stores, trust relationships.",
    PRIVILEGE_ESCALATION: "Become a more privileged principal on something you already hold.",
    LATERAL_MOVEMENT: "Use what you hold to reach a new host or account closer to the objective.",
    COLLECTION: "Gather the objective data you can now reach.",
    EXFILTRATION: "Demonstrate the data could leave — proving impact, minimally and safely.",
    PERSISTENCE: "Maintain access (REQUIRES explicit RoE authorization and approval).",
    DEFENSE_EVASION: "Reduce detectability (REQUIRES explicit RoE authorization and approval).",
}

# Stages that are sensitive and must not be attempted without explicit sign-off.
GATED = {PERSISTENCE, DEFENSE_EVASION}


@dataclass
class StageState:
    stage: str
    status: str = NOT_STARTED
    notes: list = field(default_factory=list)


class KillChain:
    def __init__(self, path: str | Path | None = None):
        self._stages: dict[str, StageState] = {s: StageState(stage=s) for s in STAGES}
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            try:
                for row in json.loads(self._path.read_text(encoding="utf-8")):
                    st = StageState(**row)
                    self._stages[st.stage] = st
            except (json.JSONDecodeError, TypeError):
                pass

    def mark(self, stage: str, status: str, note: str = "") -> None:
        st = self._stages.get(stage)
        if st is None:
            return
        st.status = status
        if note:
            st.notes.append(note)
        self._flush()

    def status(self, stage: str) -> str:
        st = self._stages.get(stage)
        return st.status if st else NOT_STARTED

    def achieved(self) -> list[str]:
        return [s for s, st in self._stages.items() if st.status == ACHIEVED]

    # -- the decision that makes this a red team ------------------------------

    def recommend(self, access, objective=None) -> list[str]:
        """Which stages actually advance us, given what we hold and where we're going."""
        holdings = access.held() if access else []
        kinds = {n.kind for n in holdings}
        has_foothold = bool(kinds & {PRINCIPAL, HOST, CREDENTIAL})

        # Already at an objective target? Collect and prove impact.
        if objective is not None and access is not None:
            for c in objective.outstanding():
                if c.target and access.distance_to(c.target) == 0:
                    return [COLLECTION, EXFILTRATION]

        if not has_foothold:
            # No foothold: the only things that matter are surface and a way in.
            return ([RECON, INITIAL_ACCESS] if self.status(RECON) != ACHIEVED
                    else [INITIAL_ACCESS])

        # We hold something. Is there a known route to the objective?
        if objective is not None and access is not None:
            for c in objective.outstanding():
                if c.target and (access.distance_to(c.target) or 0) > 0:
                    return [LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, COLLECTION]

        # Foothold but no known path: widen what we can see and what we can become.
        order = [DISCOVERY, CREDENTIAL_ACCESS, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT]
        pending = [s for s in order if self.status(s) != ACHIEVED]
        return pending or [COLLECTION]

    def briefing(self, access=None, objective=None) -> str:
        done = self.achieved()
        lines = ["[KILL CHAIN]"]
        lines.append("  achieved: " + (", ".join(done) if done else "(nothing yet)"))
        recs = self.recommend(access, objective)
        lines.append("[NEXT STAGE — choose actions that advance these]")
        for s in recs:
            gate = "  (GATED: needs explicit authorization + approval)" if s in GATED else ""
            lines.append(f"  -> {s}: {STAGES.get(s, '')}{gate}")
        return "\n".join(lines)

    def summary(self) -> dict:
        return {"achieved": len(self.achieved()),
                "stages": {s: st.status for s, st in self._stages.items()}}

    def _flush(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(st) for st in self._stages.values()], indent=2),
            encoding="utf-8")
