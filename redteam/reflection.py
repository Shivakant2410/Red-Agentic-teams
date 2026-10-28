"""LLM strategist — the orchestrator's self-reflection loop.

Gen-1's orchestrator was deterministic but *blind between rounds*: it kept running the
same round structure regardless of what the swarm was actually learning. Rounds that
produced nothing cost exactly as much as rounds that confirmed a foothold, and nobody
ever looked across rounds and asked "is this working?".

Reflection closes that loop. After each exploit round (and its verify pass), a strong
model is handed a compact, FACTUAL digest — objective progress, confirmed findings,
failed hypotheses from the attack tree, kill-chain stage, stalled-verify signals from
the audit log — and must return strict JSON:

    assessment        one-paragraph read of where the engagement stands
    what_worked[]     concrete things that produced evidence
    what_failed[]     concrete dead ends worth NOT retrying as-is
    prioritize[]      {technique, target} pairs to attack next round (tree boost)
    deprioritize[]    techniques to push down the tree this run
    focus_next[]      short directives injected into every specialist's next briefing

Failure policy: reflection is an AMPLIFIER, never a dependency. Any parse/validation
failure, any LLM error, any budget exhaustion -> returns None and the run continues
exactly as Gen-1 did. The digest is deterministic (derived from stores, not model
narration), so a bad reflection can nudge priorities but cannot invent findings.
"""

from __future__ import annotations

import json
import re

REFLECTION_SYSTEM = """You are the strategy reviewer for an authorized red-team engagement \
run by a swarm of specialist agents (recon / exploit / verify / access / logic). You see a \
factual digest of one completed round. Your job: judge whether the current strategy is \
working, and redirect the swarm if it is not.

Rules:
- Base every claim ONLY on the digest. Do not invent findings or access that is not listed.
- prioritize/deprioritize are nudges applied to a fixed safety-checked attack tree — they \
cannot create or authorize anything, only reorder already-in-scope technique/target pairs.
- Be decisive: if a technique produced nothing across rounds, say to deprioritize it; if a \
foothold is confirmed but unpressed, say to prioritize the chain follow-ups.
- Respond with STRICT JSON only (no markdown fences, no prose): \
{"assessment": str, "what_worked": [str], "what_failed": [str], \
"prioritize": [{"technique": str, "target": str}], "deprioritize": [str], "focus_next": [str]}
Keep it tight: assessment <= 5 sentences, each list <= 5 items."""


def build_digest(*, objective_text: str, round_no: int, objective=None, findings=None,
                 attack_tree=None, killchain=None, audit_tail: list[dict] | None = None,
                 notes_so_far: list[str] | None = None) -> str:
    """Deterministic, factual digest of the engagement state for the strategist."""
    findings = findings or []
    lines: list[str] = [f"OBJECTIVE: {objective_text}", f"ROUND JUST COMPLETED: {round_no}"]

    if objective is not None:
        done, total = objective.progress()
        lines.append(f"OBJECTIVE PROGRESS: {done}/{total} criteria met"
                     + (" — ACHIEVED" if getattr(objective, "achieved", False) else ""))
        outstanding = objective.outstanding()[:4]
        if outstanding:
            lines.append("OUTSTANDING: " + "; ".join(c.description for c in outstanding))

    confirmed = [f for f in findings if getattr(f, "confidence", "") == "confirmed"]
    pending = [f for f in findings if getattr(f, "confidence", "") == "pending_verification"]
    dead = [f for f in findings
            if getattr(f, "confidence", "") in ("falsified", "not_reproducible")]
    lines.append(f"CONFIRMED FINDINGS ({len(confirmed)}): " + (
        "; ".join(f"{f.severity}:{f.title} @ {f.target}" for f in confirmed[:8]) or "none"))
    lines.append(f"PENDING VERIFICATION ({len(pending)}): " + (
        "; ".join(f.title for f in pending[:5]) or "none"))
    if dead:
        lines.append(f"DEAD FINDINGS ({len(dead)}): " + "; ".join(f.title for f in dead[:5]))

    if attack_tree is not None:
        chain = attack_tree.confirmed_chain()
        actionable = attack_tree.actionable(limit=8)
        lines.append("CONFIRMED TREE NODES: " + (
            ", ".join(n.id for n in chain[:10]) or "none"))
        lines.append("TOP OF UNTESTED FRONTIER: " + (
            ", ".join(n.id for n in actionable) or "empty"))

    if killchain is not None:
        achieved = killchain.achieved()
        lines.append("KILL CHAIN STAGES ACHIEVED: " + (", ".join(achieved) or "none (no foothold yet)"))

    if notes_so_far:
        lines.append("PREVIOUS REFLECTIONS (latest last): " + " | ".join(notes_so_far[-3:]))

    if audit_tail:
        # Compact signal extraction: only failure-shaped audit events, nothing else.
        interesting = {}
        for ev in audit_tail:
            etype = ev.get("event", "")
            for prefix in ("llm.rotate", "llm.degenerate", "agent.repeat_blocked",
                           "agent.stalled_out", "orchestrator.verify_incomplete",
                           "orchestrator.swarm_worker_error", "kali_exec.refused",
                           "agent.no_models"):
                if etype.startswith(prefix):
                    interesting[prefix] = interesting.get(prefix, 0) + 1
        if interesting:
            lines.append("FAILURE SIGNALS THIS ROUND (audit counts): " +
                         ", ".join(f"{k}={v}" for k, v in sorted(interesting.items())))

    return "\n".join(lines)


def extract_json(text: str) -> dict | None:
    """Robust strict-JSON extraction: strip code fences, find the outermost object."""
    if not text:
        return None
    text = re.sub(r"```(?:json)?", "", text).strip().strip("`")
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[start:i + 1])
                    return parsed if isinstance(parsed, dict) else None
                except json.JSONDecodeError:
                    return None
    return None


def _clean_str(value: object, limit: int = 400) -> str:
    return str(value or "").strip()[:limit]


def validate_reflection(data: dict | None) -> dict | None:
    """Normalize + validate the strategist's JSON; None on anything unusable."""
    if not isinstance(data, dict):
        return None
    assessment = _clean_str(data.get("assessment"))
    if not assessment:
        return None
    out = {
        "assessment": assessment,
        "what_worked": [_clean_str(x, 200) for x in (data.get("what_worked") or []) if str(x).strip()][:5],
        "what_failed": [_clean_str(x, 200) for x in (data.get("what_failed") or []) if str(x).strip()][:5],
        "prioritize": [],
        "deprioritize": [_clean_str(x, 100) for x in (data.get("deprioritize") or []) if str(x).strip()][:5],
        "focus_next": [_clean_str(x, 200) for x in (data.get("focus_next") or []) if str(x).strip()][:5],
    }
    for item in (data.get("prioritize") or [])[:5]:
        if isinstance(item, dict) and str(item.get("technique", "")).strip():
            out["prioritize"].append({
                "technique": _clean_str(item.get("technique"), 100),
                "target": _clean_str(item.get("target"), 300),
            })
    return out


def coach_note(reflection: dict) -> str:
    """The briefing fragment injected into every specialist's next run objective."""
    parts = [f"[COACH'S NOTES — round strategist]\n{reflection['assessment']}"]
    if reflection["focus_next"]:
        parts.append("Focus: " + "; ".join(reflection["focus_next"]))
    if reflection["what_failed"]:
        parts.append("Known dead ends this run: " + "; ".join(reflection["what_failed"]))
    return "\n".join(parts)


def reflect(client, *, objective_text: str, round_no: int, objective=None, findings=None,
            attack_tree=None, killchain=None, audit_tail: list[dict] | None = None,
            notes_so_far: list[str] | None = None, on_text=None) -> dict | None:
    """One strategist call over the round digest. Returns the validated reflection dict,
    or None on ANY failure (the run never depends on this)."""
    digest = build_digest(objective_text=objective_text, round_no=round_no,
                          objective=objective, findings=findings, attack_tree=attack_tree,
                          killchain=killchain, audit_tail=audit_tail,
                          notes_so_far=notes_so_far)
    messages = [
        {"role": "system", "content": REFLECTION_SYSTEM},
        {"role": "user", "content": digest + "\n\nReturn the strict JSON reflection now."},
    ]
    try:
        result = client.chat(messages, tools=None, role="plan")
        data = extract_json(result.message.get("content") or "")
        validated = validate_reflection(data)
        if validated is not None and on_text:
            on_text(f"[strategist] {validated['assessment']}")
        return validated
    except Exception:
        return None
