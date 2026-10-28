"""Task routing — send each job to the cheapest model that can do it.

Frontier labs run one big model for everything. Our edge is the opposite: parsing,
triage, and summarization are cheap, high-volume jobs that a small model does fine, while
planning and proof-of-concept authoring need the strongest model available. Routing by
*role* is what turns "free-model roulette" into a deliberate cost/quality strategy.

For free models we can't rank by price (all $0), so we classify by capability signal:
small/fast models (haiku/mini/flash/small, or low param counts) serve cheap roles; larger
instruct models serve the hard roles. A role always falls back to the other pool if its
own is empty, so the agent never stalls for lack of a perfectly-tiered model.
"""

from __future__ import annotations

import re

# Roles the agent asks for.
PARSE = "parse"        # extract structure from tool output
TRIAGE = "triage"      # cheap yes/no relevance judgments
SUMMARY = "summary"    # compress context
PLAN = "plan"          # decide the next move over graph state
POC = "poc"            # author/refine an exploit proof-of-concept
DEFAULT = "plan"

_CHEAP_ROLES = {PARSE, TRIAGE, SUMMARY}

# Name signals for a small/fast model.
_SMALL_SIGNALS = re.compile(
    r"(haiku|mini|flash|small|nano|tiny|lite|\b[1-9]b\b|\b1[0-2]b\b|8b|7b|3b|phi|gemma)",
    re.IGNORECASE,
)


def is_small_model(model_id: str, context_len: int | None = None) -> bool:
    if _SMALL_SIGNALS.search(model_id):
        return True
    # Very small context windows also imply a lighter model.
    if context_len is not None and context_len <= 16000:
        return True
    return False


def classify_pools(model_ids: list[str], context_lens: dict[str, int] | None = None
                  ) -> dict[str, list[str]]:
    """Split candidate ids into 'cheap' and 'strong', preserving input order."""
    context_lens = context_lens or {}
    cheap, strong = [], []
    for mid in model_ids:
        (cheap if is_small_model(mid, context_lens.get(mid)) else strong).append(mid)
    return {"cheap": cheap, "strong": strong}


def candidates_for_role(pools: dict[str, list[str]], role: str) -> list[str]:
    """Ordered candidate list for a role: preferred pool first, then the other as fallback."""
    if role in _CHEAP_ROLES:
        primary, secondary = pools.get("cheap", []), pools.get("strong", [])
    else:
        primary, secondary = pools.get("strong", []), pools.get("cheap", [])
    seen, ordered = set(), []
    for mid in [*primary, *secondary]:
        if mid not in seen:
            seen.add(mid)
            ordered.append(mid)
    return ordered
