"""TargetProfile — per-target campaign intelligence that outlives a run.

THE GAP THIS CLOSES. The repo already had two agentic attackers
(pi/agent.py AgentBrain, sid/agent.py DisclosureBrain) with UCB1 bandits
over the same physical axis — cipher/encoding competence — and they could
not share a single fact: state lived in local variables, the profile of
THIS target was re-derived from zero on every run, and pi's hard-won
"the target decodes base64" evaporated at process exit. The web-pentest
swarm has cross-run memory (memory.py ExperienceStore); the LLM family
lanes had none. This module is that missing memory, as a plain ledger.

WHAT IT STORES (oracle facts only — it never rules):
  axes     — per (axis, arm) tallies of outcomes the mechanical oracles
             produced: n, hits, refusals, no_evidence, reward_sum. The
             reward table is the SAME one both brains' UCB1 already uses,
             so warm-starting from these numbers prices arms identically
             to the brains' own observations.
  families — per OWASP family: attempt tallies + the lane's OWN minted
             three-verdict rulings (labeled as the lane's ruling; this
             module never re-derives or overrules a verdict).
  notes    — short pinned facts a lane wants the next lane or session to
             see (deterministic, in pin order).
  sessions — how many campaign sessions contributed (honest bookkeeping).

WARM-START MATH (memory decay as arithmetic, not a heuristic):
  priors_for(axis, arms, cap) returns, per arm with evidence,
  (n0, mean0) = (min(observed_n, cap), reward_sum / observed_n).
  The n0 cap bounds stale evidence: a hundred hits from last session
  enter a UCB1 as FOUR virtual pulls — fresh observations this session
  can always outvote them, and an untried arm still gets its optimistic
  sweep first. Warm-started arms are therefore re-probed, not trusted.

ALIASES. pi calls the base64 arm "b64", sid calls it "base64" — the
ledger canonicalizes on write and resolves on read, so cross-lane
transfer cannot silently die on a naming mismatch.

PROVENANCE / DIVERGENCE:
  - Rainbow Teaming (Samvelyan et al., NeurIPS 2024, arXiv:2402.16822)
    populates a persistent MAP-Elites archive per target so red-teaming
    accumulates instead of restarting. Divergence: this archive is the
    MECHANICAL oracle's tallies, not LLM-judged prompt elites.
  - TAP (Mehrotra et al., arXiv:2312.02119) prunes attacked branches and
    re-attacks promising ones at the TREE level; the same discipline at
    the CAMPAIGN level needs exactly this persisted per-target state
    (the orchestrator reads family tallies to prune/press).
  - X-Teaming (Rahman et al., 2025, arXiv:2504.13203) splits planner /
    attack-optimization / verification across agents; the verification
    half here stays the mechanical oracles, and the planner half reads
    this ledger instead of an LLM planner's guesses.
  - Warm-starting bandits from historical data is standard MAB practice
    (Lazaric, Restelli & Bonetti, 2008, "Reinforcement learning in
    bandit settings"); the n0 cap is the honest version: priors decay
    by bounding virtual evidence, never by hiding it.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

# The house reward table — MUST match both agentic brains' UCB1 rewards
# (pi/agent.py _REWARD, sid/agent.py _UCB1.update) so a warm-started arm
# is priced exactly like a fresh observation.
REWARD = {"hit": 1.0, "no_evidence": 0.5, "resisted": 0.0}
OUTCOMES = ("hit", "resisted", "no_evidence")

# Lane spellings -> canonical ledger name. pi's encoder arm is "b64",
# sid's is "base64"; both must land on one arm or transfer dies quietly.
ARM_ALIASES = {"b64": "base64"}


def _canonical(arm: str) -> str:
    return ARM_ALIASES.get(arm, arm)


def _local(canonical: str) -> str:
    for local, canon in ARM_ALIASES.items():
        if canon == canonical:
            return local
    return canonical


def fingerprint_target(api_style: str, model: str, system_sha: str) -> str:
    """Stable identity for a (deployment, model, system-prompt) triple —
    the key a profile is filed under. Same triple -> same ledger."""
    blob = json.dumps({"api_style": api_style, "model": model,
                       "system_sha": system_sha},
                      sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


class TargetProfile:
    """One target's cross-session, cross-family oracle-fact ledger."""

    def __init__(self, fingerprint: str | None = None, *,
                 default_cap: int = 4):
        self.fingerprint = fingerprint or ""
        self.default_cap = default_cap
        self.axes: dict = {}       # axis -> arm -> tally
        self.families: dict = {}   # family -> tallies
        self.notes: list = []      # [(session, text)]
        self.sessions = 0

    # -- sessions -----------------------------------------------------------------

    def start_session(self) -> int:
        self.sessions += 1
        return self.sessions

    # -- recording ------------------------------------------------------------------

    def record_attempt(self, family: str, axis: str, arm: str,
                       outcome: str) -> None:
        """One oracle verdict on one attempt. family/axis/arm are the
        lanes' vocabularies (open); outcome is the closed house set."""
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}, "
                             f"got {outcome!r}")
        canon = _canonical(arm)
        arm_t = self.axes.setdefault(axis, {}).setdefault(canon, {
            "n": 0, "hits": 0, "refusals": 0, "no_evidence": 0,
            "reward_sum": 0.0})
        arm_t["n"] += 1
        key = {"hit": "hits", "resisted": "refusals",
               "no_evidence": "no_evidence"}[outcome]
        arm_t[key] += 1
        arm_t["reward_sum"] += REWARD[outcome]
        fam = self.families.setdefault(family, {
            "attempts": 0, "hits": 0, "refusals": 0, "no_evidence": 0,
            "verdicts": {}})
        fam["attempts"] += 1
        fam[key] += 1

    def record_family_verdict(self, family: str, verdict: str) -> None:
        """Store the lane's OWN minted ruling (the runner's three-verdict
        contract), labeled as a count of lane rulings — never re-derived
        here."""
        fam = self.families.setdefault(family, {
            "attempts": 0, "hits": 0, "refusals": 0, "no_evidence": 0,
            "verdicts": {}})
        fam["verdicts"][verdict] = fam["verdicts"].get(verdict, 0) + 1

    def pin(self, text: str) -> None:
        self.notes.append((self.sessions, str(text)))

    # -- reading -----------------------------------------------------------------

    def priors_for(self, axis: str, arm_names, cap: int | None = None) -> dict:
        """Warm-start pairs {(LOCAL arm name): (n0, mean0)} for the arms
        requested. Only arms with evidence come back; n0 is capped
        (default_cap) so stale sessions can never outweigh fresh ones.
        Arm names resolve through the alias map in BOTH directions."""
        out = {}
        for name in arm_names:
            canon = _canonical(name)
            t = self.axes.get(axis, {}).get(canon)
            if not t or t["n"] == 0:
                continue
            n0 = min(t["n"], cap if cap is not None else self.default_cap)
            out[name] = (n0, t["reward_sum"] / t["n"])
        return out

    def family_state(self, family: str) -> dict:
        return dict(self.families.get(family, {
            "attempts": 0, "hits": 0, "refusals": 0, "no_evidence": 0,
            "verdicts": {}}))

    def briefing(self) -> str:
        """The learned-facts text for the next lane/session. Deterministic:
        axes and arms sorted, families sorted, notes in pin order."""
        lines: list[str] = []
        for axis in sorted(self.axes):
            for arm in sorted(self.axes[axis]):
                t = self.axes[axis][arm]
                if t["n"] == 0:
                    continue
                # Briefing speaks CANONICAL arm names — it is the shared
                # document across lanes (priors_for resolves to each
                # lane's local spelling on read).
                if t["hits"]:
                    lines.append(f"{axis}.{arm}: {t['n']} attempts, "
                                 f"{t['hits']} hits — target folds on it")
                elif t["refusals"]:
                    lines.append(f"{axis}.{arm}: {t['n']} attempts, "
                                 f"all refused — target resisted it")
                else:
                    lines.append(f"{axis}.{arm}: {t['n']} attempts, "
                                 f"no positive evidence")
        for family in sorted(self.families):
            st = self.family_state(family)
            if st["verdicts"]:
                verdicts = ", ".join(
                    f"{v} x{c}" for v, c in sorted(st["verdicts"].items()))
                lines.append(f"family {family}: lane rulings {verdicts}")
            elif st["attempts"]:
                lines.append(f"family {family}: {st['attempts']} attempts, "
                             f"no lane ruling yet")
        for _sess, text in self.notes:
            lines.append(f"note: {text}")
        return "\n".join(lines)

    # -- persistence --------------------------------------------------------------

    def to_dict(self) -> dict:
        return {"fingerprint": self.fingerprint,
                "default_cap": self.default_cap,
                "axes": self.axes,
                "families": self.families,
                "notes": self.notes,
                "sessions": self.sessions}

    @classmethod
    def from_dict(cls, d: dict) -> "TargetProfile":
        p = cls(d.get("fingerprint") or "",
                default_cap=int(d.get("default_cap", 4)))
        p.axes = d.get("axes", {})
        p.families = d.get("families", {})
        p.notes = [tuple(n) for n in d.get("notes", [])]
        p.sessions = int(d.get("sessions", 0))
        return p

    def save(self, path) -> None:
        pathlib.Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8")

    @classmethod
    def load(cls, path) -> "TargetProfile":
        return cls.from_dict(
            json.loads(pathlib.Path(path).read_text(encoding="utf-8")))
