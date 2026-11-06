"""Findings as capabilities: chain search over the preconditions/grants graph.

Each finding declares:
  preconditions : what an attacker needs (e.g. "any account", "order_id of victim")
  grants        : what it yields  (e.g. "read any order", "credit self balance")

A chain is a path in the reachability graph where finding B's preconditions
are satisfied by finding A's grants (confused-deputy model, dossier S8.5).
Severity of a chain = max(severity of members) + escalation note.
"""

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_chains(findings):
    chains = []
    by_grant = {}
    for f in findings:
        for g in f.get("grants", []):
            by_grant.setdefault(g, []).append(f)

    for f in findings:
        for pre in f.get("preconditions", []):
            for g, donors in by_grant.items():
                if _satisfies(g, pre) and g not in f.get("grants", []):
                    for donor in donors:
                        if donor["id"] == f["id"]:
                            continue
                        chains.append(_mk_chain(donor, f))

    # dedupe by member ids
    seen, out = set(), []
    for c in chains:
        key = tuple(sorted(c["members"]))
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _satisfies(grant, precondition):
    grant, precondition = grant.lower(), precondition.lower()
    if precondition.startswith("any "):        # "any account" — always satisfiable
        return False
    if "any" not in precondition:              # precondition pins a specific object
        return False
    if "order" in precondition and "order" in grant and "any" in grant:
        return True
    if precondition in grant:
        return True
    return False


def _mk_chain(a, b):
    sev = max(a["severity"], b["severity"], key=lambda s: _SEV_ORDER.get(s, 0))
    return {"chain_id": "CH-%s-%s" % (a["id"], b["id"]),
            "members": [a["id"], b["id"]],
            "path": "%s --(%s)--> %s" % (a["id"], _bridge(a, b), b["id"]),
            "severity": sev,
            "impact": _impact(a, b)}


def _bridge(a, b):
    if "read any order" in a.get("grants", []):
        return "supplies arbitrary order_id"
    return "grants preconditions"


def _impact(a, b):
    grants_b = ", ".join(b.get("grants", []))
    return ("Chaining %s (grants: %s) with %s yields an unauthenticated-to-"
            "financial-integrity path: %s." % (a["id"], ", ".join(a.get("grants", [])),
                                               b["id"], grants_b))
