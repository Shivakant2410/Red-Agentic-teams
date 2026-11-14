"""The 8 transition mutant operators as PURE transforms over step plans.

A step plan is a list of dicts:
    {"name": str, "method": str, "path": str, "body": dict|None,
     "principal": str, "headers": dict|None, "op": str|None, "race_n": int|None}

Operators never touch the network — they only rewrite plans — so they are
unit-testable and replayable. The executor consumes the mutated plan.
"""

OPS = ("SKIP", "REPLAY", "REORDER", "PARTIAL", "NEGATIVE", "CROSS-USER",
       "INTERRUPT", "IDEMPOTENCE")


def _clone(steps):
    return [dict(s, body=dict(s["body"]) if isinstance(s.get("body"), dict) else s.get("body"))
            for s in steps]


def skip(steps, i, name=None):
    """Remove step i entirely (skip a mandatory transition, e.g. payment)."""
    out = _clone(steps)
    out.pop(i)
    if out:
        out[0]["op"] = "SKIP"
        if name:
            out[0]["name"] = name
    return out


def replay(steps, i, k=2, name=None):
    """Duplicate step i, k total executions (state guards / idempotency)."""
    out = _clone(steps)
    dup = dict(out[i])
    dup["op"] = "REPLAY"
    dup["replay_copies"] = k
    if name:
        dup["name"] = name
    return out[:i] + [dup] * (k - 1) + out[i:]


def reorder(steps, i, j, name=None):
    """Swap two writes so effects land in an unintended order."""
    out = _clone(steps)
    out[i], out[j] = out[j], out[i]
    out[min(i, j)]["op"] = "REORDER"
    if name:
        out[min(i, j)]["name"] = name
    return out


def partial(steps, i, drop, name=None):
    """Strip a required field from step i's body (half-applied transition)."""
    out = _clone(steps)
    if isinstance(out[i].get("body"), dict) and drop in out[i]["body"]:
        del out[i]["body"][drop]
    out[i]["op"] = "PARTIAL"
    out[i]["dropped_field"] = drop
    if name:
        out[i]["name"] = name
    return out


def negative(steps, i, field, name=None):
    """Negate an integer field on step i (sign validation)."""
    out = _clone(steps)
    b = out[i].get("body")
    if isinstance(b, dict) and isinstance(b.get(field), int):
        b[field] = -b[field]
    out[i]["op"] = "NEGATIVE"
    out[i]["negated_field"] = field
    if name:
        out[i]["name"] = name
    return out


def cross_user(steps, i, principal, name=None):
    """Re-authenticate one step as another principal (ownership boundary)."""
    out = _clone(steps)
    out[i]["principal"] = principal
    out[i]["op"] = "CROSS-USER"
    if name:
        out[i]["name"] = name
    return out


def interrupt(steps, i, n=8, name=None):
    """Flag step i for last-byte-synchronised racing (concurrency)."""
    out = _clone(steps)
    out[i]["op"] = "INTERRUPT"
    out[i]["race_n"] = n
    if name:
        out[i]["name"] = name
    return out


def idempotence(steps, i, key="sf-key-1", name=None):
    """Re-send step i with a stable Idempotency-Key (server must dedupe)."""
    out = _clone(steps)
    dup = dict(out[i])
    dup["op"] = "IDEMPOTENCE"
    dup["headers"] = dict(dup.get("headers") or {}, **{"Idempotency-Key": key})
    if name:
        dup["name"] = name
    return out[:i] + [dup, out[i]] + out[i + 1:]
