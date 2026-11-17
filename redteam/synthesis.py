"""synthesis — the evidence-join layer: turn accumulated observations into attack ideas.

THE GAP THIS CLOSES (audited 2026-11 against the live loop):

The system's selector is class-based, not evidence-based. AttackTree.sync() seeds the
SAME entry techniques on EVERY endpoint, and an AttackNode is just
(technique, target, status, bucket). When a swarm worker claims `access.idor on
/api/orders/1042` it receives only TECHNIQUES["access.idor"].description — one generic
sentence — and must re-derive the entire attack idea from a blank page: which param,
which identities, what would the request even look like. Meanwhile the run state holds
exactly the observations that make that node attackable — PARAMETER nodes with
reflection attrs (webinspect), session identities (SessionStore), held access
(AccessGraph), proven facts (FindingStore) — and NOTHING joins them. Composition is
left to the LLM's chance notice inside a bounded briefing. A human red teamer's core
skill is precisely this join: "identifier-shaped path + two held identities = a
two-request differential with concrete requests." This module does that join
deterministically, so workers inherit reasoning instead of re-deriving it.

DESIGN RULES (honoring the C1 contract — docs/ADR-001):

  1. Synthesis never SELECTS. The attack tree's actionable()/claim() order is
     untouched; ideas are keyed by (technique, target) and only ENRICH nodes that
     already exist on the frontier. No idea can create, authorize, or widen work.
  2. Synthesis never PROVES. Its output is a DRAFT for the claiming worker to verify
     and adapt — every claim still goes through the normal k-of-n + negative-control
     pipeline, and only verify_finding_independently says "confirmed".
  3. Pure state reasoning. No network, no sandbox, no binaries, nothing registered in
     build_registry (agents do not call it; the orchestrator feeds it). A synthesis
     failure degrades to an audit record — the swarm runs exactly as before.
  4. Every idea carries its evidence. rationale names the actual observations and
     where they live (node keys, session labels, finding ids) so the worker — and the
     hypothesis registry's EvidenceRefs — can trace WHY this node looked attackable.
     An idea without evidence is refused by construction (the rules are the evidence
     patterns; no pattern, no idea).

RULES (each = evidence pattern -> draft check; deterministic, unit-tested):

  R1 identity_differential  -> access.idor
     identifier-shaped path segment or parameter node + >=2 held identities
     -> two-request differential (same object, identity A vs identity B).
  R2 unauth_baseline        -> access.control
     protection-shaped path (admin/profile/settings/...) reachable in a held session
     -> unauthenticated replay of the same request as the draft baseline check.
  R3 reflection_ready       -> xss.reflected
     a PARAMETER node whose specials_survive=True (the inspector saw quote/tag
     characters survive) -> reflected_unescaped check on a fresh marker. Escaped
     reflections produce NO idea (proof budget is not spent on dead oracles).
  R4 credential_reuse       -> auth.test
     a credential-shaped finding (title/cwe) + an auth-shaped endpoint
     -> try_credential plan pointing at both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .attack_tree import TECHNIQUES

# ---------------------------------------------------------------------------
# Evidence & idea types
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    """One piece of run state an idea was derived FROM. ref points at where the
    full material lives (graph node key, session label, finding id) — the same
    provenance discipline EvidenceRef enforces."""
    source: str      # which layer saw it: graph | sessions | access | findings
    kind: str        # endpoint | parameter | identity | finding
    ref: str         # node key / session label / finding id
    detail: str      # bounded human-readable fact


@dataclass
class AttackIdea:
    technique: str
    target: str
    rationale: str                 # the JOIN sentence: why THIS target, from WHAT
    evidence: list[Observation] = field(default_factory=list)
    expected_behavior: str = ""    # what the app should do if not vulnerable
    proposed_test: str = ""        # draft check: concrete requests + conditions
    verify_hint: str = ""
    score: float = 0.0


# ---------------------------------------------------------------------------
# Evidence patterns (shared by the rules; each is unit-tested)
# ---------------------------------------------------------------------------

_ID_PATH = re.compile(
    r"/(?:\d{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)",
    re.IGNORECASE)
_ID_PARAM = re.compile(
    r"(^(user|account|acct|order|invoice|doc|file|item|record|profile|message|customer|tenant)[_-]?)?id(s)?$"
    r"|^(uid|uuid|guid|email|username)$", re.IGNORECASE)
_PROTECTED_SEGMENT = re.compile(
    r"(?i)/(admin|profile|settings|account|dashboard|console|manage|internal|private|users)(/|$)")
_AUTH_SEGMENT = re.compile(
    r"(?i)(login|signin|sign-in|auth|session|token|oauth|sso)")
_CREDENTIAL_FINDING = re.compile(
    r"(?i)password|secret|token|api[ ._-]?key|credential|private key|hash")
_CREDENTIAL_CWES = {"CWE-200", "CWE-256", "CWE-257", "CWE-521", "CWE-522", "CWE-798"}

_MAX_EVIDENCE_PER_IDEA = 6


def _endpoint_urls(ctx) -> list[str]:
    try:
        from .knowledge import ENDPOINT
        return [n.key for n in (ctx.graph.nodes(ENDPOINT) if ctx.graph else [])]
    except Exception:
        return []


def _param_nodes(ctx) -> list[tuple[str, dict]]:
    """(url#param, attrs) for every PARAMETER node the inspectors folded."""
    try:
        from .knowledge import PARAMETER
        return [(n.key, dict(n.attrs or {}))
                for n in (ctx.graph.nodes(PARAMETER) if ctx.graph else [])]
    except Exception:
        return []


def _session_labels(ctx) -> list[str]:
    try:
        return list(ctx.sessions.labels()) if ctx.sessions else []
    except Exception:
        return []


def _findings(ctx) -> list:
    try:
        return list(ctx.findings.all()) if ctx.findings else []
    except Exception:
        return []


def _session_evidence(ctx, source: str) -> list[Observation]:
    return [Observation(source="sessions", kind="identity", ref=label,
                        detail=f"held identity: session {label!r}")
            for label in _session_labels(ctx)][:2]   # two is what a differential needs


# ---------------------------------------------------------------------------
# The rules. Each returns None when its evidence pattern does not hold —
# no pattern, no idea; ideas without evidence are refused by construction.
# ---------------------------------------------------------------------------


def _rule_identity_differential(ctx, ep: str) -> AttackIdea | None:
    """R1: identifier-shaped target + two held identities -> IDOR differential."""
    labels = _session_labels(ctx)
    if len(labels) < 2:
        return None
    path_id = _ID_PATH.search(ep)
    param_hits = [(key, attrs) for key, attrs in _param_nodes(ctx)
                  if key.startswith(f"{ep}#") or key.split("#", 1)[0].rstrip("/") == ep.rstrip("/")
                  and _ID_PARAM.search(key.split("#", 1)[-1] or "")]
    if not path_id and not param_hits:
        return None
    what = (f"numeric/UUID path id" if path_id
            else f"identifier parameter {param_hits[0][0].split('#')[-1]!r}")
    a, b = labels[0], labels[1]
    if path_id:
        payload_req = f"GET {ep} as session {b!r}"
    else:
        pname = param_hits[0][0].split("#")[-1]
        payload_req = (f"GET {ep} with {pname}=<sibling id> as session {b!r}")
    return AttackIdea(
        technique="access.idor", target=ep,
        rationale=(f"{ep} exposes {what} and we hold two distinct identities "
                   f"({a!r}, {b!r}) — request the SAME object as both; if identity B "
                   f"reaches identity A's object, access control is broken. Evidence: "
                   f"{what} on the endpoint path/params, sessions store holds both labels."),
        evidence=_session_evidence(ctx, ep) + [Observation(
            source="graph", kind="endpoint", ref=ep, detail=f"{what} observed on target")],
        expected_behavior=("the server scopes object access to the authenticated principal; "
                           "identity B gets 403/404 or an object that is not A's"),
        proposed_test=(
            f"verify_vulnerability(check_type='proof'): requests = "
            f"{{baseline: GET {ep} as session {a!r}, payload: {payload_req}}}; "
            f"conditions = status(payload)==200 AND body(payload) differs from "
            f"body(baseline). Draft — fill in the real sibling object id before proving."),
        verify_hint=("prove with verify_vulnerability (k-of-n, negative control is the "
                     "baseline identity); crosscheck not needed — the differential IS "
                     "the second method"),
    )


def _rule_unauth_baseline(ctx, ep: str) -> AttackIdea | None:
    """R2: protection-shaped path reachable in a held session -> unauth replay."""
    if not _session_labels(ctx) or not _PROTECTED_SEGMENT.search(ep):
        return None
    return AttackIdea(
        technique="access.control", target=ep,
        rationale=(f"{ep} sits under a protection-shaped path and was mapped while we "
                   f"held a session — the mapped response came from an AUTHENTICATED "
                   f"context, so an unauthenticated replay is the missing baseline."),
        evidence=_session_evidence(ctx, ep)[:1] + [Observation(
            source="graph", kind="endpoint", ref=ep,
            detail="protection-shaped path (admin/profile/settings/...) mapped in-session")],
        expected_behavior="unauthenticated request is refused (401/403/redirect to login)",
        proposed_test=(
            f"verify_vulnerability(check_type='http'): request = GET {ep} with NO session "
            f"headers; expect_status=200; body_regex = <a marker taken from the SESSIONED "
            f"response — pull it with one http_probe as the held session first>. "
            f"Draft — the body_regex must name real protected content, not a guess."),
        verify_hint="prove with verify_vulnerability; the sessioned response is the control",
    )


def _rule_reflection_ready(ctx, ep: str) -> AttackIdea | None:
    """R3: the inspector saw specials survive -> the reflection is worth proving."""
    for key, attrs in _param_nodes(ctx):
        if not (attrs.get("reflected") and attrs.get("specials_survive")):
            continue
        url, param = key.split("#", 1)
        if url.rstrip("/") != ep.rstrip("/"):
            continue
        context = attrs.get("context") or "unknown"
        return AttackIdea(
            technique="xss.reflected", target=ep,
            rationale=(f"the reflection inspector mapped param {param!r} on {ep} into a "
                       f"live {context} sink (specials survive encoding) — the sink is "
                       f"worth exactly one context-correct proof, not payload blasting."),
            evidence=[Observation(source="graph", kind="parameter", ref=key,
                                  detail=f"reflected=True specials_survive=True "
                                         f"context={context}")],
            expected_behavior=("the marker arrives entity-encoded or stripped; only "
                               "unescaped special characters prove script context"),
            proposed_test=(
                f"verify_vulnerability(check_type='proof'): request = GET {url} with "
                f"{param}=rtx<unique> adapted to the {context} context; condition = "
                f"reflected_unescaped on that exact marker. Sink context: {context}."),
            verify_hint=("the inspector's specials probe already ran — spend proof budget "
                         "here, do NOT re-map the reflection"),
        )
    return None


def _rule_credential_reuse(ctx, ep: str) -> AttackIdea | None:
    """R4: credential-shaped finding + auth-shaped endpoint -> reuse attempt."""
    creds = [f for f in _findings(ctx)
             if getattr(f, "cwe", "") in _CREDENTIAL_CWES
             or _CREDENTIAL_FINDING.search(getattr(f, "title", "") or "")]
    if not creds or not _AUTH_SEGMENT.search(ep):
        return None
    f = creds[0]
    f_id = getattr(f, "id", "finding")
    f_title = (getattr(f, "title", "") or "")[:80]
    return AttackIdea(
        technique="auth.test", target=ep,
        rationale=(f"finding {f_id} ({f_title}) exposed credential-shaped material and "
                   f"{ep} is an authentication surface — the reuse question is whether "
                   f"harvested material opens it."),
        evidence=[Observation(source="findings", kind="finding", ref=f_id,
                              detail=f"credential-shaped finding: {f_title}")],
        expected_behavior="harvested material is scoped (rotated, per-session, bound to a device)",
        proposed_test=(
            f"try_credential with candidates traced to finding {f_id} against the "
            f"{ep} probe endpoint; success = authenticated session material returned. "
            f"Draft — never replay a credential against a host outside scope."),
        verify_hint=("try_credential holds its own evidence trail; a hit must still go "
                     "through prove_privilege before the access graph credits it"),
    )


_RULES = (_rule_identity_differential, _rule_unauth_baseline,
          _rule_reflection_ready, _rule_credential_reuse)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def synthesize(ctx, limit: int = 8) -> list[AttackIdea]:
    """Join run state into ranked, evidence-carrying attack ideas.

    Deterministic and side-effect free: reads graph/sessions/findings, never touches
    the network or the selector. Dedupes per (technique, target); ranks by evidence
    count + the technique's own priority; caps at `limit`. Any failure degrades to
    fewer/empty ideas — never a raise."""
    ideas: dict[tuple[str, str], AttackIdea] = {}
    try:
        for ep in _endpoint_urls(ctx):
            for rule in _RULES:
                try:
                    idea = rule(ctx, ep)
                except Exception:
                    continue
                if idea is None:
                    continue
                idea.evidence = idea.evidence[:_MAX_EVIDENCE_PER_IDEA]
                idea.score = len(idea.evidence) + TECHNIQUES.get(
                    idea.technique, TECHNIQUES["info.sensitive"]).priority / 100.0
                key = (idea.technique, idea.target)
                if key not in ideas or idea.score > ideas[key].score:
                    ideas[key] = idea
    except Exception:
        return []
    return sorted(ideas.values(), key=lambda i: i.score, reverse=True)[:limit]


def idea_for(ideas: list[AttackIdea], technique: str, target: str) -> AttackIdea | None:
    """The enrichment lookup: a tree node claims (technique, target); if synthesis
    has an idea for it, the worker inherits the evidence and the draft check."""
    for idea in ideas:
        if idea.technique == technique and idea.target == target:
            return idea
    return None


def brief(idea: AttackIdea, max_chars: int = 1400) -> str:
    """The bounded worker-injection block: evidence, expected behavior, draft check.
    This is the text that ends the blank-page handoff — it is explicitly a DRAFT for
    the worker to verify and adapt, never a proof. Bounds are PER SECTION: a verbose
    rationale must never starve the draft check that follows it."""
    rationale = idea.rationale[:420]
    lines = [
        "SYNTHESIZED EVIDENCE (deterministic join of run observations — a DRAFT for you "
        "to verify/adapt, not a proof):",
        f"WHY: {rationale}",
        "EVIDENCE:"]
    lines += [f"  - [{o.source}/{o.kind}] {str(o.detail)[:150]} (ref: {o.ref})"
              for o in idea.evidence]
    if idea.expected_behavior:
        lines.append(f"EXPECTED (if NOT vulnerable): {str(idea.expected_behavior)[:200]}")
    if idea.proposed_test:
        lines.append(f"DRAFT CHECK: {idea.proposed_test}")
    if idea.verify_hint:
        lines.append(f"HINT: {str(idea.verify_hint)[:250]}")
    return "\n".join(lines)[:max_chars]
