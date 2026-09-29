"""Adversarial falsification — try to DISPROVE a finding before recording it.

OpenAnt measured that an adversarial verification stage eliminated 49.5% of flagged
findings (376 -> 190). Their falsifier is an LLM simulating a constrained attacker. We
implement the deterministic, model-agnostic core of the same idea: a NEGATIVE CONTROL.

The logic is plain science. A proof shows "payload produces signal." That is only evidence
of a vulnerability if a *benign* request does NOT produce the same signal. So we re-run the
identical conditions with the attack payload swapped for a harmless control:

  - control does NOT satisfy the conditions -> the signal is attack-caused  -> CONFIRMED
  - control DOES satisfy the conditions     -> the signal was there anyway  -> FALSIFIED

This kills the biggest false-positive class we hit in run 7 ("the endpoint returns 200 and
contains that string regardless of what I send"), needs no frontier model, and it cannot
be talked around by a confident LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .proof import eval_condition

# Structured verdicts (OpenAnt-style) rather than a bare boolean.
CONFIRMED = "confirmed"
FALSIFIED = "falsified"
NOT_REPRODUCIBLE = "not_reproducible"
REJECTED = "rejected"


@dataclass
class FalsificationResult:
    falsified: bool
    detail: str
    control_conditions_held: bool = False
    details: list[str] = field(default_factory=list)


def run_negative_control(fetchers: dict, conditions: list, control_fetch,
                         replaces: str) -> FalsificationResult:
    """Re-evaluate the proof with `replaces` swapped for a benign control request.

    fetchers: name -> fetch() for the real proof requests
    control_fetch: fetch() for the benign control
    replaces: which named request the control stands in for (usually "payload")
    """
    if replaces not in fetchers:
        return FalsificationResult(
            falsified=False,
            detail=f"control_replaces '{replaces}' is not one of the requests; control skipped")

    responses = {name: fn() for name, fn in fetchers.items() if name != replaces}
    responses[replaces] = control_fetch()

    details, all_held = [], True
    for cond in conditions:
        try:
            passed, detail = eval_condition(cond, responses)
        except KeyError as exc:
            return FalsificationResult(False, f"control evaluation error: {exc}")
        all_held = all_held and passed
        details.append(("held " if passed else "absent ") + detail)

    if all_held:
        return FalsificationResult(
            falsified=True,
            detail=("FALSIFIED: the benign control produced the same signal, so the result is "
                    "not caused by the payload."),
            control_conditions_held=True, details=details)
    return FalsificationResult(
        falsified=False,
        detail="control did not reproduce the signal — the effect is attack-caused.",
        control_conditions_held=False, details=details)
