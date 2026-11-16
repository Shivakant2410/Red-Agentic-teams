"""Warm-start assist — the TargetProfile as a prior source for OTHER
engines.

THE GAP THIS CLOSES. The brain's warm-start assist worked INSIDE the
brain: the pi/sid/sc bands read TargetProfile.priors_for as virtual
pulls. The llmred Thompson campaign (redteam/llmred + BanditStore) ran on
its own llmred_bandit.json and learned THIS target from zero — even when
the brain already held a family dossier from earlier sessions. This
module is the bridge, in BOTH directions:

  READ  seed_bandit_from_profile: family hit rates become Beta
        pseudo-counts on VIRGIN (strategy, family) arms — the same
        warm-start math as TargetProfile.priors_for, expressed through
        the BanditStore's seed() contract.
  WRITE writeback_profile_from_summary: the campaign's oracle facts
        (per-objective verdict tallies + the family verdict) land back
        in the ledger, so the NEXT brain campaign inherits them. One
        writer per fact: the bandit keeps its own llmred_bandit.json,
        the profile keeps the dossier; neither overwrites the other.

THE NO-CERTAINTY RULE (BanditStore.seed enforces 0 < p < 1): a family
that folded on EVERY attempt does not get p = 1.0 — it gets 0.95 —
because the profile is a dossier, not a law. The clamp is the honest
version of "the target folded so far, and Thompson still owes
exploration the chance to say otherwise." Strength is capped exactly
like priors_for (default_cap): stale sessions enter as bounded
pseudo-counts, fresh evidence always outvotes them.

THREE CONTRACTS (inherited from BanditStore.seed, all kept):
  (1) DATA WINS — a prior never overrides evidence: arms with observed
      outcomes are refused (seed() returns False and we skip them);
  (2) NO CERTAINTY — p is clamped to [0.05, 0.95] on BOTH ends;
  (3) FACTS ONLY — the ledger stores oracle outcomes; transport errors
      are not target facts and are never recorded.

PROVENANCE / DIVERGENCE: Thompson sampling with informative Beta priors
already exists in this repo — priors.py seeds PUBLIC exploit intel
(EPSS/KEV) as pseudo-counts. This provider seeds PER-TARGET MEASURED
evidence from the brain's ledger instead: the same mechanism, a
different knowledge source, and the two compose (an arm may carry public
intel as its shape prior and this dossier as its target prior — seed()
refuses whichever arrives second, so the first writer wins and the
provenance string says which).
"""

from __future__ import annotations

SOURCE = "target-profile"


def profile_prior(profile, family: str, cap: int | None = None):
    """(p, strength) for one OWASP family from the ledger's own tallies —
    or None when the family has no evidence. p = hit rate, clamped;
    strength = min(attempts, cap): the same bounded-virtual-evidence
    discipline TargetProfile.priors_for applies to bandit warm starts."""
    st = profile.family_state(family)
    attempts = int(st.get("attempts", 0))
    if attempts <= 0:
        return None
    strength = float(min(attempts,
                         cap if cap is not None else profile.default_cap))
    if strength < 1.0:
        return None
    p_raw = st.get("hits", 0) / attempts
    return min(max(p_raw, 0.05), 0.95), strength


def seed_bandit_from_profile(bandit, profile, arms, *,
                             source: str = SOURCE) -> list:
    """Seed VIRGIN (strategy, family) arms from the ledger. `arms` is a
    list of (technique, bucket, family) triples; returns the arms that
    were actually seeded (virgin + family with evidence), each as
    {technique, bucket, family, p, strength}. Data-wins refusals are
    silent skips — the arm keeps its own evidence."""
    seeded = []
    for technique, bucket, family in arms:
        prior = profile_prior(profile, family)
        if prior is None:
            continue
        p, strength = prior
        if bandit.seed(str(technique), str(bucket), p,
                       strength=strength, source=source):
            seeded.append({"technique": str(technique),
                           "bucket": str(bucket), "family": str(family),
                           "p": round(p, 4), "strength": strength})
    return seeded


def writeback_profile_from_summary(profile, summary) -> None:
    """Record an llmred campaign's oracle facts into the ledger. Reads the
    summary's per-objective tallies (the same shape summary.json carries);
    the family key is the objective's OWASP code (LLM01:2026 -> LLM01).
    The family verdict is the campaign's OWN bucketed outcome — labeled
    as a ruling count, never re-derived. Errors are transport, not target
    facts: they update nothing."""
    for oid, st in (summary.get("objectives") or {}).items():
        family = str(st.get("owasp", "")).split(":")[0]
        if not family:
            continue
        for _ in range(int(st.get("successes", 0) or 0)):
            profile.record_attempt(family, "llmred_objective", oid, "hit")
        for _ in range(int(st.get("blocked", 0) or 0)):
            profile.record_attempt(family, "llmred_objective", oid,
                                   "resisted")
        for _ in range(int(st.get("undetermined", 0) or 0)):
            profile.record_attempt(family, "llmred_objective", oid,
                                   "no_evidence")
        verdict = ("succeeded" if st.get("successes")
                   else "resisted" if st.get("blocked")
                   else "inconclusive")
        profile.record_family_verdict(family, verdict)
