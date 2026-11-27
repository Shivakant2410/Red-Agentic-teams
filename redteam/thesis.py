"""Attack theses — reasoning as a first-class, logged artifact.

A scanner emits findings. A senior operator (the Bishop Fox / Wiz red-team
bar) first writes down an ATTACK THESIS: given THIS specific target, what do I
believe is exploitable, WHY, which invariant does the server wrongly trust, how
does a small primitive CHAIN into real financial / ATO / data impact, what
exact observable would prove it, and what would refute it. The thesis is the
thing you can read, audit and argue with BEFORE any traffic is sent — and it is
what makes a human pentest report valuable versus a tool dump.

This module turns that into a real object the exploit and logic specialists
must produce. An LLM generates theses from the recon evidence; each is scored
NOVELTY x IMPACT x EVIDENCE so target-specific chained reasoning ranks above
generic "try IDOR on numeric IDs"; the ranked theses seed attack-tree nodes
(carrying their rationale) so the existing claim/verify/bandit machinery
executes them. Verify stays the adversary: a thesis is a BELIEF, never a
finding, until an independent reproduction confirms it.

Design mirrors reflection.py: robust JSON extraction, strict validation, and
graceful None/empty on any failure — a run never DEPENDS on the thesis layer,
it is lifted by it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Callable

# Impact tiers -> a multiplier. Financial loss / account takeover is what the
# programs pay most for and what a scanner never reaches, so it dominates.
_IMPACT_WEIGHT = {
    "financial": 1.0,   # money moves wrongly (fraud, double-spend, free goods)
    "ato": 0.95,        # account takeover of another user
    "data": 0.8,        # unauthorized read/exfil of another user's data
    "privesc": 0.75,    # role/permission escalation
    "integrity": 0.6,   # tamper with another user's objects/state
    "dos": 0.2,         # availability — usually out of scope / low value
    "info": 0.25,       # disclosure with no proven business impact
}

# Generic technique classes a scanner / top-10-only AI already finds. A thesis
# whose belief reduces to one of these, with no app-specific chain, is NOT the
# deep work — it is penalised so target-specific reasoning ranks above it.
_GENERIC_MARKERS = (
    "reflected xss", "stored xss", "sql injection", "sqli", "open redirect",
    "missing header", "cookie flag", "clickjack", "csrf token", "verbose error",
    "directory listing", "version disclosure", "banner", "default credential",
    "generic idor", "numeric id", "autocomplete", "tabnabbing",
)

# Chain language — presence of a multi-step path from primitive to impact is the
# signal of depth. A one-shot "endpoint X leaks Y" is shallower than
# "A on B's object -> refund flow -> payout to me".
_CHAIN_MARKERS = ("then", "chain", "pivot", "->", "which lets", "so that",
                  "combined with", "leads to", "escalate", "resulting in")


@dataclass
class AttackThesis:
    """One falsifiable attack belief about THIS target.

    Not a finding (verify owns that) and not a generic technique (the catalog
    owns those): the operator's written reasoning, scored and logged.
    """
    id: str
    target_model: str      # what this system IS / how it creates+guards value
    belief: str            # what is exploitable here, specifically
    rationale: str         # WHY — the evidence + the reasoning
    invariant: str         # the server-trusted assumption believed breakable
    chain: list[str] = field(default_factory=list)  # primitive -> flow -> impact
    predicted_proof: str = ""   # the exact observable that confirms it
    kill_condition: str = ""    # what refutes it (prune without spending budget)
    impact: str = "info"        # one of _IMPACT_WEIGHT keys
    technique: str = ""         # attack-tree technique id to seed (optional)
    target: str = ""            # concrete URL/endpoint the thesis attacks
    confidence: float = 0.5     # self-scored 0..1, calibrated by evidence below
    # Computed at validation time — not supplied by the model.
    novelty: float = 0.0
    score: float = 0.0
    source: str = "llm"

    def briefing(self) -> str:
        """Compact human-readable form injected into the specialist's objective
        so the agent attacks its OWN written reasoning, not a generic menu."""
        lines = [f"THESIS {self.id} (score {self.score:.2f}, impact {self.impact})",
                 f"  belief: {self.belief}",
                 f"  invariant trusted (and breakable): {self.invariant}"]
        if self.chain:
            lines.append("  chain: " + " -> ".join(self.chain))
        if self.predicted_proof:
            lines.append(f"  prove by: {self.predicted_proof}")
        if self.kill_condition:
            lines.append(f"  drop if: {self.kill_condition}")
        return "\n".join(lines)


def extract_json_array(text: str) -> list | None:
    """Pull the outermost JSON array (the model returns a list of theses).
    Falls back to a single object wrapped in a list. None if unusable."""
    if not text:
        return None
    text = re.sub(r"```(?:json)?", "", text).strip().strip("`")
    start = text.find("[")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "[":
                depth += 1
            elif text[i] == "]":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[start:i + 1])
                        return parsed if isinstance(parsed, list) else None
                    except json.JSONDecodeError:
                        return None
    # Single-object fallback.
    obj_start = text.find("{")
    if obj_start != -1:
        depth = 0
        for i in range(obj_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(text[obj_start:i + 1])
                        return [parsed] if isinstance(parsed, dict) else None
                    except json.JSONDecodeError:
                        return None
    return None


def _clean(value: object, limit: int = 600) -> str:
    return str(value or "").strip()[:limit]


def _novelty(belief: str, rationale: str, chain: list[str]) -> float:
    """1.0 = target-specific chained reasoning; low = a generic scanner class.

    Penalise generic-class language; reward an explicit multi-step chain and
    concrete app-specific nouns in the reasoning. This is what makes the system
    PREFER depth over the textbook bugs everyone's tool already finds.
    """
    hay = (belief + " " + rationale + " " + " ".join(chain)).lower()
    score = 0.55  # neutral prior
    if any(m in hay for m in _GENERIC_MARKERS):
        score -= 0.35
    chain_hits = sum(1 for m in _CHAIN_MARKERS if m in hay) + max(0, len(chain) - 1)
    score += min(0.4, 0.12 * chain_hits)   # an explicit chain is the depth signal
    # Concrete, app-specific reasoning tends to be longer and specific; a bare
    # one-liner belief ("IDOR on /users/{id}") is usually the shallow case.
    if len(rationale) > 180:
        score += 0.1
    return max(0.0, min(1.0, score))


def _evidence_support(thesis: dict, evidence_keys: set[str]) -> float:
    """How grounded is this thesis in what recon ACTUALLY observed? A thesis
    naming a real observed endpoint/param is grounded; one invented from thin
    air is speculative and ranked lower (but not dropped — recon has gaps)."""
    target = _clean(thesis.get("target"), 300).lower()
    if not evidence_keys:
        return 0.5
    if target and any(target in k or k in target for k in evidence_keys):
        return 1.0
    # Partial: any observed path token appears in the belief/rationale.
    hay = (_clean(thesis.get("belief")) + " " + _clean(thesis.get("rationale"))).lower()
    toks = {t for k in evidence_keys for t in re.findall(r"[a-z0-9_]{3,}", k.lower())}
    if toks and any(t in hay for t in toks):
        return 0.7
    return 0.3


def validate_thesis(data: dict, idx: int, evidence_keys: set[str]) -> AttackThesis | None:
    """Normalise + score one model-proposed thesis; None if unusable."""
    if not isinstance(data, dict):
        return None
    belief = _clean(data.get("belief"))
    invariant = _clean(data.get("invariant"))
    if not belief or not invariant:
        return None  # a thesis without a belief + a trusted-invariant is noise
    rationale = _clean(data.get("rationale"), 800)
    chain = [_clean(c, 200) for c in (data.get("chain") or []) if str(c).strip()][:8]
    impact = _clean(data.get("impact"), 20).lower()
    if impact not in _IMPACT_WEIGHT:
        impact = "info"
    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    novelty = _novelty(belief, rationale, chain)
    evidence = _evidence_support(data, evidence_keys)
    impact_w = _IMPACT_WEIGHT[impact]
    # The core ranking: NOVELTY x IMPACT x EVIDENCE, nudged by self-confidence.
    # Geometric-style product so a thesis must be strong on ALL three — a
    # generic high-impact guess (low novelty) and a novel no-impact musing (low
    # impact) both fall below a grounded, novel, high-impact chain.
    score = round(novelty * impact_w * (0.5 + 0.5 * evidence) * (0.6 + 0.4 * confidence), 4)

    return AttackThesis(
        id=f"T{idx:02d}",
        target_model=_clean(data.get("target_model"), 600),
        belief=belief,
        rationale=rationale,
        invariant=invariant,
        chain=chain,
        predicted_proof=_clean(data.get("predicted_proof"), 400),
        kill_condition=_clean(data.get("kill_condition"), 300),
        impact=impact,
        technique=_clean(data.get("technique"), 60),
        target=_clean(data.get("target"), 300),
        confidence=confidence,
        novelty=round(novelty, 3),
        score=score,
    )


EXPLOIT_SYSTEM = (
    "You are the lead offensive engineer on a top-tier red team (Bishop Fox / "
    "Wiz caliber). You do NOT run a payload library — you REASON about THIS "
    "specific target and write down an attack thesis a senior reviewer could "
    "audit before any packet is sent. Given the recon evidence, produce the "
    "theses that a scanner and a top-10-only tool would MISS: target-specific, "
    "chained, high-impact. For TECHNICAL primitives (exploit lens): weak or "
    "mutable object references, trust placed in client-supplied values, "
    "token/session handling, request/response tampering, SSRF that reaches "
    "something real — but only where you can reason a concrete chain to impact. "
    "Avoid generic findings with no chain (reflected XSS, missing headers, "
    "version disclosure) unless you can chain them into real damage.\n"
    "Return a STRICT JSON ARRAY of theses, each: {target_model, belief, "
    "rationale, invariant, chain:[step,...], predicted_proof, kill_condition, "
    "impact:(financial|ato|data|privesc|integrity|info), technique, target}. "
    "No prose outside the JSON."
)

LOGIC_SYSTEM = (
    "You are the lead offensive engineer on a top-tier red team (Bishop Fox / "
    "Wiz caliber) focused on BUSINESS LOGIC — the bugs a scanner cannot find "
    "and the program pays most for. Given the recon evidence, first MODEL the "
    "application: its actors, the objects they own, and the money / ownership / "
    "state-transition flows between them. Then name the invariants the server "
    "TRUSTS (price computed server-side; pay-before-ship; escrow releases only "
    "after delivery; act only on your own objects; a refund/credit can't exceed "
    "what was paid; a state can't move backward; an action can't be raced). "
    "Produce theses that attack a trusted invariant and CHAIN a small primitive "
    "into financial loss or account takeover. Cross-account reasoning must only "
    "ever touch objects the tester owns on both sides.\n"
    "Return a STRICT JSON ARRAY of theses, each: {target_model, belief, "
    "rationale, invariant, chain:[step,...], predicted_proof, kill_condition, "
    "impact:(financial|ato|data|privesc|integrity|info), technique, target}. "
    "No prose outside the JSON."
)


def generate_theses(client, *, lens: str, evidence_digest: str = "",
                    evidence_keys: set[str] | None = None,
                    objective_text: str = "", max_theses: int = 6,
                    log: Callable[..., None] | None = None,
                    world_model_projection: dict | None = None) -> list[AttackThesis]:
    """One LLM call that turns recon evidence into ranked attack theses.

    lens: "exploit" (technical primitives) or "logic" (business-logic/chaining).
    Returns theses sorted best-first; [] on any failure (the run never depends
    on this layer — it is lifted by it, exactly like reflection.py).
    """
    system = LOGIC_SYSTEM if lens == "logic" else EXPLOIT_SYSTEM
    facts = (world_model_projection or {}).get("facts", [])
    if facts:
        evidence_label = "TYPED WORLD MODEL (compact, evidence-backed facts; inferred facts remain labelled):"
        evidence_content = json.dumps(world_model_projection, ensure_ascii=False,
                                       sort_keys=True)[:7000]
    else:
        evidence_label = "RECON EVIDENCE (what we actually observed on the target):"
        evidence_content = evidence_digest[:8000]
    user = (f"OBJECTIVE: {objective_text}\n\n"
            f"{evidence_label}\n{evidence_content}\n\n"
            f"Use only the attached evidence references; do not invent principals, ownership, "
            f"workflow states, or trust boundaries. Return up to {max_theses} theses "
            f"as a strict JSON array now, best/highest-impact first.")
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": user}]
    try:
        result = client.chat(messages, tools=None, role="plan")
        raw = extract_json_array(result.message.get("content") or "")
    except Exception:
        return []
    if not raw:
        return []
    keys = evidence_keys or set()
    out: list[AttackThesis] = []
    for i, item in enumerate(raw[: max_theses * 2], start=1):
        t = validate_thesis(item, i, keys)
        if t is not None:
            out.append(t)
    out.sort(key=lambda t: t.score, reverse=True)
    out = out[:max_theses]
    # Renumber ids in ranked order so T01 is the top bet.
    for rank, t in enumerate(out, start=1):
        t.id = f"T{rank:02d}"
    if log:
        log("thesis.generated", lens=lens, count=len(out),
            top_score=out[0].score if out else 0.0,
            top=out[0].belief[:120] if out else "")
    return out


def theses_briefing(theses: list[AttackThesis], limit: int = 5) -> str:
    """The block injected into a specialist's objective so it attacks the
    ranked written reasoning instead of a generic technique menu."""
    if not theses:
        return ""
    head = ("[ATTACK THESES — reason first, then prove. Pursue these in order; "
            "each is a falsifiable belief about THIS target, not a generic class. "
            "Prove with the normal confirm/verify tools; a thesis counts for "
            "nothing until independently reproduced.]")
    return head + "\n" + "\n".join(t.briefing() for t in theses[:limit])


def write_theses(path, theses: list[AttackThesis]) -> None:
    """Persist the run's theses as an inspectable artifact (thesis.jsonl) — the
    record of HOW the agent reasoned, which is what a human report's approach
    section is. Best-effort; never breaks a run."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for t in theses:
                fh.write(json.dumps(asdict(t), default=str) + "\n")
    except Exception:
        pass
