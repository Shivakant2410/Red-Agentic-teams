"""Relationship and duplicate detection — two stages, CANDIDATES ONLY.

Stage 1 (deterministic): compare normalized signatures — (asset_ref, weakness_class,
security_boundary, principal, action, preconditions). Equal signatures ⇒ DUPLICATE_OF
candidate; same asset+weakness with differing attributes ⇒ RELATED_TO; equal signature
with opposite expected-behavior polarity (a conservative keyword classifier; unknown
wording yields NO candidate) ⇒ CONTRADICTS.

Stage 2 (semantic, pluggable): the SemanticMatcher protocol. Phase C1 ships only
NullSemanticMatcher (no external embedding/LLM service — the rule) and a deterministic
LexicalOverlapMatcher (token Jaccard) so the plumbing is exercised without any service
dependency. Anything the semantic stage produces is origin="semantic_candidate" with a
confidence score, and — like everything here — advisory.

CRITICAL RULES (enforced by design, tested explicitly):

  - candidates are computed, never persisted, never authoritative;
  - candidates never delete, merge, reword, or resolve anything;
  - SUPERSEDES is never machine-generated — only an explicit, reasoned link() on the
    registry records it;
  - wording similarity without signature agreement cannot produce a DUPLICATE_OF
    candidate (lexical near-matches across different assets are the classic false
    positive, and they stay suggestions even when they do fire);
  - the original hypothesis and its provenance always survive — running the matcher
    has zero effect on registry state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from .hypotheses import (CONTRADICTS, DUPLICATE_OF, RELATED_TO, SUPERSEDES,
                         Hypothesis, normalize_asset, normalize_weakness)

ORIGIN_DETERMINISTIC = "deterministic"
ORIGIN_SEMANTIC = "semantic_candidate"
ORIGIN_AGENT = "agent"          # only link() on the registry writes this origin


@dataclass(frozen=True)
class HypothesisSignature:
    """The normalized comparison key. Built from the hypothesis, never from prose
    alone: two hypotheses are signature-equal only when asset, weakness class, and
    the security-shape attributes all agree."""
    asset: str
    weakness: str
    boundary: str
    principal: str
    action: str
    preconditions: frozenset[str]

    @classmethod
    def of(cls, hyp: Hypothesis) -> "HypothesisSignature":
        return cls(asset=normalize_asset(hyp.asset_ref),
                   weakness=normalize_weakness(hyp.weakness_class),
                   boundary=(hyp.security_boundary or "").strip().lower(),
                   principal=(hyp.principal or "").strip().lower(),
                   action=(hyp.action or "").strip().lower(),
                   preconditions=frozenset(hyp.preconditions or ()))


@dataclass(frozen=True)
class RelationshipCandidate:
    """An advisory suggestion. Never stored by the registry; a human/agent turns one
    into an authoritative link() with their own attribution."""
    kind: str
    other_id: str
    reason: str
    origin: str                      # deterministic | semantic_candidate
    confidence: float = 1.0          # semantic stage only; deterministic = 1.0


class SemanticMatcher(Protocol):
    """Stage-2 interface. A future embedding- or LLM-based evaluator implements this
    and is passed to HypothesisRegistry.candidate_relationships(matcher=...); nothing
    else in the system changes. MUST NOT make network/service calls a test depends on."""
    def candidates(self, hypothesis: Hypothesis, others: list[Hypothesis]) -> list[RelationshipCandidate]: ...


class NullSemanticMatcher:
    """The Phase C1 default: no external service, no suggestions. Exists so callers
    can always pass an explicit stage-2 matcher and get well-defined no-op behavior."""

    def candidates(self, hypothesis: Hypothesis,
                   others: list[Hypothesis]) -> list[RelationshipCandidate]:
        return []


# -- polarity (deterministic CONTRADICTS support) --------------------------------------

_VULNERABLE_WORDS = (
    "granted", "grants", "succeeds", "accessible", "bypass", "bypassed", "accepted",
    "accepted.", "executes", "differs", "leaks", "leaked", "reflected", "unescaped",
    "200", "returns data", "reveals", "exposed", "reachable", "retrieves",
)
_CONTROL_WORDS = (
    "denied", "rejects", "blocked", "refused", "403", "401", "unchanged", "identical",
    "not accessible", "cannot", "same response", "no difference", "controls",
    "remains", "inaccessible", "unchanged.", "does not differ", "enforced",
)


def _polarity(expected_behavior: str) -> str | None:
    """'vulnerable' | 'control_holds' | None. Conservative by construction: mixed or
    unknown wording yields None, and None never becomes a CONTRADICTS candidate — a
    missed contradiction costs one unnoticed candidate; a false one would poison a
    human reviewer's queue."""
    text = (expected_behavior or "").lower()
    vuln = any(w in text for w in _VULNERABLE_WORDS)
    ctrl = any(w in text for w in _CONTROL_WORDS)
    if vuln and not ctrl:
        return "vulnerable"
    if ctrl and not vuln:
        return "control_holds"
    return None


# -- stage 1: deterministic matcher ------------------------------------------------------

class DeterministicMatcher:
    """Signature-based candidate generation. Pure function of (hypothesis, others)."""

    def candidates(self, hypothesis: Hypothesis,
                   others: list[Hypothesis]) -> list[RelationshipCandidate]:
        sig = HypothesisSignature.of(hypothesis)
        out: list[RelationshipCandidate] = []
        for other in others:
            if other.hypothesis_id == hypothesis.hypothesis_id:
                continue
            osig = HypothesisSignature.of(other)
            if sig.asset != osig.asset:
                continue    # different asset ⇒ never a duplicate candidate, whatever the wording
            if sig.weakness != osig.weakness:
                if sig.asset and sig.weakness and osig.weakness:
                    out.append(RelationshipCandidate(
                        kind=RELATED_TO, other_id=other.hypothesis_id,
                        reason=(f"same asset {sig.asset!r}, different weakness "
                                f"({sig.weakness} vs {osig.weakness})"),
                        origin=ORIGIN_DETERMINISTIC))
                continue
            # same asset + same weakness from here on. Rule order matters: two
            # hypotheses describing the SAME scenario (full signature equal) with
            # OPPOSITE expected behavior contradict each other — that is the honest
            # label, not DUPLICATE_OF. Ambiguous wording (no clear polarity) never
            # produces a contradiction and falls through to the signature rules.
            pol_a = _polarity(hypothesis.expected_behavior)
            pol_b = _polarity(other.expected_behavior)
            if sig == osig:
                if pol_a and pol_b and pol_a != pol_b:
                    out.append(RelationshipCandidate(
                        kind=CONTRADICTS, other_id=other.hypothesis_id,
                        reason=(f"same signature with opposite expected behavior "
                                f"({pol_a} vs {pol_b})"),
                        origin=ORIGIN_DETERMINISTIC))
                else:
                    out.append(RelationshipCandidate(
                        kind=DUPLICATE_OF, other_id=other.hypothesis_id,
                        reason=("identical normalized signature (asset, weakness, "
                                "boundary, principal, action, preconditions)"),
                        origin=ORIGIN_DETERMINISTIC))
                continue
            out.append(RelationshipCandidate(
                kind=RELATED_TO, other_id=other.hypothesis_id,
                reason=("same asset+weakness, differing "
                        + ", ".join(_differing(sig, osig))),
                origin=ORIGIN_DETERMINISTIC))
        return out


_DIFF_FIELDS = (("boundary", "security boundary"), ("principal", "principal"),
                ("action", "action"), ("preconditions", "preconditions"))


def _differing(a: HypothesisSignature, b: HypothesisSignature) -> list[str]:
    diffs = []
    for attr, label in _DIFF_FIELDS:
        if getattr(a, attr) != getattr(b, attr):
            diffs.append(label)
    return diffs or ["details"]


# -- stage 2: deterministic lexical overlap (plumbing exercise, still advisory) ---------

_WORD_RE = re.compile(r"[a-z0-9]{3,}")


class LexicalOverlapMatcher:
    """Token-Jaccard over claim + expected_behavior + preconditions. Deterministic,
    offline, conservative (default threshold 0.9, minimum token count 8 — short
    claims overlap trivially and would spam candidates). Produced candidates are
    DUPLICATE_OF suggestions with origin='semantic_candidate': they name what a
    human (or a future embedding/LLM evaluator) should look at, and nothing more."""

    def __init__(self, threshold: float = 0.9, min_tokens: int = 8):
        self.threshold = max(float(threshold), 0.5)
        self.min_tokens = max(int(min_tokens), 4)

    def _tokens(self, hyp: Hypothesis) -> set[str]:
        text = " ".join([hyp.claim or "", hyp.expected_behavior or "",
                         *(hyp.preconditions or [])]).lower()
        return set(_WORD_RE.findall(text))

    def candidates(self, hypothesis: Hypothesis,
                   others: list[Hypothesis]) -> list[RelationshipCandidate]:
        mine = self._tokens(hypothesis)
        if len(mine) < self.min_tokens:
            return []
        out: list[RelationshipCandidate] = []
        for other in others:
            if other.hypothesis_id == hypothesis.hypothesis_id:
                continue
            theirs = self._tokens(other)
            if not theirs:
                continue
            jaccard = len(mine & theirs) / len(mine | theirs)
            if jaccard >= self.threshold:
                out.append(RelationshipCandidate(
                    kind=DUPLICATE_OF, other_id=other.hypothesis_id,
                    reason=f"lexical overlap {jaccard:.2f} >= {self.threshold:.2f} "
                           f"(candidate only — verify before linking)",
                    origin=ORIGIN_SEMANTIC, confidence=round(jaccard, 3)))
        return out


__all__ = ["HypothesisSignature", "RelationshipCandidate", "SemanticMatcher",
           "NullSemanticMatcher", "DeterministicMatcher", "LexicalOverlapMatcher",
           "ORIGIN_DETERMINISTIC", "ORIGIN_SEMANTIC", "ORIGIN_AGENT",
           "DUPLICATE_OF", "RELATED_TO", "CONTRADICTS", "SUPERSEDES"]
