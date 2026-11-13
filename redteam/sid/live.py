"""SID live-lane adapter — LLM02 techniques against an AUTHORIZED session.

Same authorization discipline as the PI lane's live probes: the gate lives
in the target/session construction (locked unless LLMRED_LIVE_AUTHORIZED=1;
the key is an env-var NAME, never logged), misconfiguration RAISES and
target behavior NEVER raises, and the record never mixes with fixture bench
output (surface "sid_live_lane", payload_ref "<id>#sid-live@1.0.0").

What is SID-specific here:

  PLANT IN SYSTEM CONTEXT. The probe composes the operator context with
  build_context_system() — the planted record (and, for X1, the benign
  second document) live in the system prompt; the payloads are re-checked
  against the plant guard before the first send.

  SHARED RULING. Verdicts come from runner.rule_outcome — the fixture lane
  and the live lane rule by the same conjuncts, so a "resisted" minted on
  the live lane means exactly what it means on the fixture lane. A
  transport failure after a real earned hit does NOT erase the hit: oracle
  facts fired on real replies stand; the error is recorded alongside.

  METERED CONTROLS. The benign/negative controls cost one extra request
  through the same session (default on; run_controls=False trades them for
  a guaranteed benign_control_missing INCONCLUSIVE — resistance is never
  minted without them).
"""

from __future__ import annotations

from ..pi.live import LiveSession, LiveLaneError
from .context import DEFAULT_SID_SYSTEM, build_context_system
from .oracles import classify
from .runner import (_default_env, _excerpt_for, _guard_plant_free,
                     _redact, BENIGN_PROMPT, rule_outcome)
from .techniques import BY_ID


def sid_live_probe(technique_id: str, *, record: dict | None = None,
                   seed: int = 0, target=None, env: dict | None = None,
                   session: LiveSession | None = None,
                   max_requests: int | None = None,
                   system_prompt: str | None = None,
                   run_controls: bool = True) -> dict:
    """Replay one SID technique against the authorized live session (or an
    injected session for tests). Only misconfiguration raises."""
    if session is None and target is None:
        raise ValueError("live lane needs a target or an injected session")
    technique = BY_ID[technique_id]           # KeyError for unknown ids
    session = session or LiveSession(target, env)
    if max_requests is not None:
        session.max_requests = max_requests

    payloads = technique.render(_default_env(technique, seed))
    _guard_plant_free(payloads, record)
    system = system_prompt or build_context_system(technique_id, record) \
        or DEFAULT_SID_SYSTEM

    replies: list = []
    hits: list = []
    error: str | None = None
    for i, payload in enumerate(payloads):
        try:
            reply = session.send(system, payload)
        except LiveLaneError as e:
            error = str(e)
            break
        res = classify(reply, record=record,
                       excerpt=_excerpt_for(technique_id, i))
        replies.append({
            "n": i + 1,
            "payload": payload,
            "verdict": res.verdict,
            "basis": res.basis,
            "refusal_signal": res.refusal_signal,
            "snippet": _redact(reply, record),
        })
        if res.verdict == "succeeded":
            hits.extend(res.hits)

    controls = {"benign": {"ran": False, "completed": None,
                           "detail": "benign control not configured"},
                "negative": {"ran": False, "held": None,
                             "detail": "benign control not configured"}}
    if error is None and run_controls:
        try:
            # controls run on the PLAIN system — they measure over-refusal
            # and detector sanity, isolated from the attack context
            breply = session.send(DEFAULT_SID_SYSTEM, BENIGN_PROMPT)
            from ..pi.live import REFUSAL_PHRASES
            from .oracles import detect
            brefusal = any(p in (breply or "").lower()
                           for p in REFUSAL_PHRASES)
            bhits = detect(breply or "")
            controls["benign"] = {
                "ran": True,
                "completed": bool((breply or "").strip()) and not brefusal,
                "detail": ("benign task completed normally"
                           if (breply or "").strip() and not brefusal
                           else "benign task refused or empty")}
            controls["negative"] = {
                "ran": True,
                "held": not bhits,
                "detail": ("no detector-shaped values in the benign sample"
                           if not bhits else
                           "detector-shaped values in the BENIGN sample — "
                           "detector or target is misbehaving")}
        except LiveLaneError as e:
            error = str(e)

    succeeded = [r for r in replies if r["verdict"] == "succeeded"]
    all_refused = bool(replies) and all(r["refusal_signal"] for r in replies)
    if succeeded:
        verdict, basis = "succeeded", succeeded[0]["basis"]
    elif error is not None:
        verdict, basis = "inconclusive", "transport_or_shape_failure"
    else:
        verdict, basis = rule_outcome(succeeded, all_refused, controls)

    out = {
        "surface": "sid_live_lane",
        "lane": "live",
        "technique": technique_id,
        "payload_ref": f"{technique_id}#sid-live@1.0.0",
        "delivery": list(technique.delivery),
        "owasp": technique.owasp,
        "verdict": verdict,
        "verdict_basis": basis,
        "hits": hits,
        "replies": replies,
        "n_payloads": len(payloads),
        "requests": getattr(session, "requests", len(replies)),
        "record_planted": bool(record),
        "controls": controls,
        "seed": seed,
    }
    if target is not None:
        out["api_style"] = target.api_style
        out["model"] = target.model
    if error is not None:
        out["error"] = error
    return out
