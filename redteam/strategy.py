"""Cross-round strategy memory (Phase B5) — the engagement gets one strategy that
lives across rounds, instead of a strategist that restarts from amnesia every round.

THE PROBLEM THIS FIXES: Gen-2's reflection loop (reflection.py) made the orchestrator
stop being blind BETWEEN rounds — but each strategist call was still stateless. Its
only memory was three raw text notes. Two failure modes followed, and they were
opposites:

- AMNESIA: round N's reflection could contradict round N-1's — re-prioritizing a
  technique it had already written off, with nothing but prose to notice.
- STICKINESS: the tree nudges apply_strategy() writes (+25 boost / -25 penalty) had
  no release path at all. A technique deprioritized once stayed suppressed for the
  whole run, even after it started producing confirmed findings — evidence could
  never beat a stale opinion.

Phase B5 replaces both with ONE object this module owns: a structured strategy state
that (a) carries directives with TTLs, (b) watches the engagement's actual evidence,
and (c) releases directives the moment evidence or expiry says so — deterministically,
no LLM required to forget.

THE THREE RULES (all enforced here, all deterministic):

1. DIRECTIVES HAVE A TTL. A "press" (prioritize) directive lives 2 rounds; an
   "avoid" (deprioritize) lives 3 — writing off a technique is a stronger claim than
   pressing one, so it outlives it, but neither is forever. `tick()` expires them.
2. EVIDENCE BEATS OPINION, BOTH WAYS. A technique that lands a CONFIRMED tree node
   after an "avoid" directive is released immediately (the write-off was wrong). A
   technique that confirms under a "press" is released too (it worked — the boost
   did its job, stop distorting the tree).
3. NO LLM IS NEEDED TO FORGET. If reflection fails (model error, budget, JSON
   garbage — the amplifier's failure policy), the strategy state still ticks and
   still releases on evidence. The worst case is always "back to the pure tree
   order", which is exactly the pre-B5 behavior, never something worse.

WHAT IT NEVER DOES: this module reorders already-in-scope work through the tree's
existing public `apply_strategy` API — the same constraint reflection has always
had. It cannot create, authorize, unlock, or widen anything. It reads evidence; it
never grades findings (that is falsify/verify's job — untouched).

WIRING (orchestrator.py): after each round, the orchestrator feeds the round's
claimed techniques (it knows them directly from its own claim loop) and the tree's
confirmed chain into `observe_round()`, ticks, hands `brief()` to the strategist's
digest (so the LLM AMENDS the state instead of restarting), maps the validated
reflection into `amend()`, and re-applies the surviving directives to the tree —
after restoring the nudge layer to neutral (`reset_tree_nudges`), so a released
directive genuinely releases.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

# Directive TTLs, in rounds (rule 1). Writing off a technique is a stronger,
# more damaging claim than pressing one — so "avoid" outlives "press", but both
# are finite. Measured cost of being wrong: press-wrong wastes <=2 rounds of
# ordering distortion; avoid-wrong wastes <=3 before evidence or expiry frees it.
TTL_PRESS = 2
TTL_AVOID = 3

# Carry at most this many directives / notes — the strategist digest stays compact
# and a hallucinating reflection cannot flood the state.
MAX_DIRECTIVES = 8
MAX_NOTES = 3


@dataclass
class Directive:
    """One live strategy decision, with the round it was made and its lifetime."""
    action: str            # "press" (node-scoped boost) | "avoid" (technique penalty)
    technique: str
    target: str = ""       # press only — the technique@target node to boost
    since_round: int = 0
    ttl: int = TTL_PRESS
    reason: str = ""

    @property
    def key(self) -> str:
        return f"{self.action}:{self.technique}@{self.target}"

    def alive(self, round_no: int) -> bool:
        return (round_no - self.since_round) < self.ttl

    def label(self) -> str:
        where = f"@{self.target}" if self.target else ""
        return f"{self.action} {self.technique}{where}"


@dataclass
class TechniqueLedger:
    """Per-technique evidence, accumulated deterministically from the run itself."""
    claims: int = 0
    confirms: int = 0
    last_seen_round: int = -1
    last_confirm_round: int = -1

    def to_dict(self) -> dict:
        return {"claims": self.claims, "confirms": self.confirms,
                "last_seen_round": self.last_seen_round,
                "last_confirm_round": self.last_confirm_round}


class EngagementStrategy:
    """The single strategy object carried across the engagement's exploit rounds.

    Thread-safety: the orchestrator calls amend/tick/observe serially after each
    round, but `brief()`/`directives_for_tree()` may be read while a round's swarm
    is still winding down — a lock keeps every view consistent, same as the
    scheduler's accounting (B3)."""

    def __init__(self, *, ttl_press: int = TTL_PRESS, ttl_avoid: int = TTL_AVOID):
        self._ttl_press = max(int(ttl_press), 1)
        self._ttl_avoid = max(int(ttl_avoid), 1)
        self._directives: dict[str, Directive] = {}     # key -> Directive
        self._notes: list[dict] = []                    # {text, since_round, ttl}
        self._ledger: dict[str, TechniqueLedger] = {}
        self._lock = threading.Lock()

    # -- evidence in (deterministic; no LLM anywhere near this) ---------------------

    def observe_round(self, round_no: int, claimed: list[str],
                      confirmed: list[str]) -> dict[str, dict]:
        """Fold one round of outcomes into the ledger: which techniques the swarm
        actually claimed (from the orchestrator's own claim loop) and which tree
        nodes confirmed (the tree's completed chain). Returns the ledger snapshot."""
        with self._lock:
            for technique in claimed:
                row = self._ledger.setdefault(technique, TechniqueLedger())
                row.claims += 1
                row.last_seen_round = max(row.last_seen_round, round_no)
            for technique in confirmed:
                row = self._ledger.setdefault(technique, TechniqueLedger())
                row.confirms += 1
                row.last_confirm_round = max(row.last_confirm_round, round_no)
            return {t: r.to_dict() for t, r in self._ledger.items()}

    # -- the strategist amends; the object owns the state ---------------------------

    def amend(self, reflection: dict, round_no: int) -> dict:
        """Map a validated reflection (reflection.py's shape) into new directives.
        Re-deciding the same thing REFRESHES the directive (same key, new TTL);
        deciding differently replaces it. Returns counts for the audit event."""
        press = avoid = notes = 0
        with self._lock:
            for item in (reflection.get("prioritize") or [])[:MAX_DIRECTIVES]:
                technique = str(item.get("technique", "")).strip()
                if not technique:
                    continue
                d = Directive(action="press", technique=technique,
                              target=str(item.get("target", "")).strip(),
                              since_round=round_no, ttl=self._ttl_press,
                              reason=str(item.get("reason", ""))[:200])
                self._directives[d.key] = d
                press += 1
            for technique in (reflection.get("deprioritize") or [])[:MAX_DIRECTIVES]:
                technique = str(technique).strip()
                if not technique:
                    continue
                # avoid is technique-scoped: one live avoid per technique
                d = Directive(action="avoid", technique=technique,
                              since_round=round_no, ttl=self._ttl_avoid,
                              reason="(strategist: repeated dead ends)")
                self._directives[d.key] = d
                avoid += 1
            for text in (reflection.get("focus_next") or [])[:MAX_NOTES]:
                text = str(text).strip()
                if text:
                    self._notes.append({"text": text[:200],
                                        "since_round": round_no,
                                        "ttl": self._ttl_avoid})
                    notes += 1
            self._notes = self._notes[-MAX_NOTES:]
        return {"press": press, "avoid": avoid, "notes": notes}

    # -- deterministic forgetting (rule 1 + rule 2) ----------------------------------

    def tick(self, round_no: int) -> list[str]:
        """Advance one round: expire TTLs, release on evidence. Returns the released
        labels (for the audit trail). Runs whether or not the strategist answered —
        forgetting is never LLM-dependent (rule 3)."""
        released: list[str] = []
        with self._lock:
            for key, d in sorted(self._directives.items()):
                evidence = self._ledger.get(d.technique)
                confirmed_since = (evidence is not None
                                   and evidence.confirms > 0
                                   and evidence.last_confirm_round >= d.since_round)
                if confirmed_since or not d.alive(round_no):
                    why = "confirmed (evidence beats opinion)" if confirmed_since \
                        else f"ttl expired ({d.ttl} rounds)"
                    released.append(f"{d.label()} — {why}")
                    del self._directives[key]
            self._notes = [n for n in self._notes
                           if (round_no - n["since_round"]) < n["ttl"]]
        return released

    # -- the tree interface (public API only, plus the documented nudge reset) -------

    def directives_for_tree(self) -> tuple[list[dict], list[str]]:
        """The live directives in `AttackTree.apply_strategy`'s exact shape."""
        with self._lock:
            press = [{"technique": d.technique, "target": d.target}
                     for d in self._directives.values() if d.action == "press"]
            avoid = [d.technique for d in self._directives.values()
                     if d.action == "avoid"]
        return press, avoid

    # -- views ------------------------------------------------------------------------

    def brief(self) -> str:
        """Compact deterministic block for the strategist's digest: what is currently
        decided, and the evidence ledger behind it. Empty string when neutral."""
        with self._lock:
            lines: list[str] = []
            for d in sorted(self._directives.values(),
                            key=lambda d: (d.action, d.technique)):
                evidence = self._ledger.get(d.technique)
                stats = (f"claims={evidence.claims} confirms={evidence.confirms}"
                         if evidence else "claims=0 confirms=0")
                lines.append(f"  - {d.label()} (since round {d.since_round}, "
                             f"ttl {d.ttl}, {stats})")
            if self._notes:
                lines.append("  carried focus: " + " | ".join(
                    n["text"] for n in self._notes))
            if self._ledger:
                ledger = " | ".join(
                    f"{t}:{r.claims}c/{r.confirms}cf"
                    for t, r in sorted(self._ledger.items()))
                lines.append(f"  ledger (claims/confirms): {ledger}")
            return "\n".join(lines)

    def state(self) -> dict:
        with self._lock:
            return {"press": sum(1 for d in self._directives.values()
                                 if d.action == "press"),
                    "avoid": sum(1 for d in self._directives.values()
                                 if d.action == "avoid"),
                    "notes": len(self._notes),
                    "ledger": {t: r.to_dict() for t, r in self._ledger.items()}}

    # -- persistence (same crash-safety contract as reflections.json) -----------------

    def to_dict(self) -> dict:
        with self._lock:
            return {"ttl_press": self._ttl_press, "ttl_avoid": self._ttl_avoid,
                    "directives": [{"action": d.action, "technique": d.technique,
                                    "target": d.target, "since_round": d.since_round,
                                    "ttl": d.ttl, "reason": d.reason}
                                   for d in self._directives.values()],
                    "notes": list(self._notes),
                    "ledger": {t: r.to_dict() for t, r in self._ledger.items()}}

    @classmethod
    def from_dict(cls, data: dict) -> "EngagementStrategy":
        obj = cls(ttl_press=data.get("ttl_press", TTL_PRESS),
                  ttl_avoid=data.get("ttl_avoid", TTL_AVOID))
        for d in data.get("directives", []):
            directive = Directive(action=d["action"], technique=d["technique"],
                                  target=d.get("target", ""),
                                  since_round=d.get("since_round", 0),
                                  ttl=d.get("ttl", TTL_PRESS),
                                  reason=d.get("reason", ""))
            obj._directives[directive.key] = directive
        obj._notes = list(data.get("notes", []))
        for t, r in data.get("ledger", {}).items():
            row = TechniqueLedger(claims=r.get("claims", 0),
                                  confirms=r.get("confirms", 0),
                                  last_seen_round=r.get("last_seen_round", -1),
                                  last_confirm_round=r.get("last_confirm_round", -1))
            obj._ledger[t] = row
        return obj


def reset_tree_nudges(tree) -> bool:
    """Restore the attack tree's strategy-nudge layer to neutral.

    WHY THIS EXISTS: `apply_strategy` is write-only — once a +25/-25 nudge lands
    there is no public way to lift it, which is exactly the stickiness Phase B5
    exists to fix. We clear precisely the two dicts apply_strategy writes (the
    documented nudge layer), so each round's application starts from the tree's own
    order and only LIVE directives distort it. The tree file is untouched; a frozen
    or oddly-shaped tree degrades to the old sticky behavior (never a crash).

    The bandit's learned win-rate is a DIFFERENT layer and is deliberately not
    touched — cross-run learning must not be erased by a per-run strategy reset."""
    try:
        tree._strategy_boost.clear()
        tree._technique_penalty.clear()
        return True
    except Exception:
        return False
