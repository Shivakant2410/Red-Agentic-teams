"""engine/surface.py — M2 (G2+G4): surface truth + open vocabulary.

GAP-PROOF band C had one shared cause: the engine's attack vocabulary was
closed at three layers (resource nouns, verbs, read-back candidates) and
every layer was keyed to the stale openapi document. M1 removed the
deferred-effect blindness (202/event shapes generate markers); M2 removes
the surface blindness with the same grounded-only discipline:

  * vocabularies are DATA (open, extensible — the M5 LLM seam's growth path
    is "extend the vocab", never "add code");
  * every probe is budget-capped, existence-oracled (404 vs 405/4xx — a
    POST-only route hit with GET answers 405, a free resource-existence
    oracle), and recorded as a surface FACT with evidence;
  * a discovery without a named consumer is not fired (band-D lesson, GV-8).

Layering: spine module — must not import the swarm. All requests go through
the shared executor, so budget, STOP kill-file and traffic provenance apply
automatically. Labour separation: a resource whose create answered 202 is an
async seam and belongs to the window driver (M1) — verb probing hands off.
"""
import json
import os
import re

# --------------------------------------------------------- vocabularies ----
# Value-resource nouns (G2): the GET probe is 1 request per noun; status
# != 404 means the resource exists. Superset discipline: the M1 seam nouns
# (ASYNC_SEAM_NOUNS in swarm/techniques.py) stay there; this list adds the
# value nouns the seam list does not cover.
VALUE_NOUNS = ("vouchers", "coupons", "credits", "payouts", "refunds",
               "rewards", "points", "invoices", "receipts", "claims",
               "wallets", "cashback", "promos", "gift-cards")

# Write verbs (G4): M1 wordlist ∪ cancel-family ∪ claim-family ∪ rebook.
# Bounded on purpose: 1 request per verb per probed object.
VERB_VOCAB = ("release", "settle", "capture", "claim", "redeem", "consume",
              "activate", "apply", "rebook", "refund", "revoke", "cancel",
              "close", "terminate", "confirm", "complete", "approve",
              "retry", "void", "fulfill")

# claim-family verbs whose second probe may reveal a single-use (409)
# check-then-act signature — the race target GV-6 needs.
CLAIM_CONSUME = ("consume", "redeem", "claim", "activate")

# Collection subpaths: _READBACK_FALLBACK's keyword list turned from a
# passive matcher into a live probe (GV-2's read half).
SUBPATH_NOUNS = ("recent", "history", "events", "audit", "all", "list",
                 "search", "stats")

MONEY_FIELD_RE = re.compile(
    r"(amount|price|rate|total|fee|cost|balance|face|credit|discount|"
    r"payout|refund|value|bonus|cents)", re.I)
PCT_FIELD_RE = re.compile(r"(_pct|percent)", re.I)
ID_VALUE_RE = re.compile(r"^[A-Z]{2,5}-[a-f0-9]{6,}$")


# ------------------------------------------------------------- helpers ----
def normalize(path):
    """'/api/shipments/{shipment_id}' -> '/api/shipments/{id}' — collapses
    braced parameters only; literal segments are preserved (the M1 dedupe
    semantics). Doc vs live comparison uses exact literals + the
    `documented` flag on discovery facts."""
    return re.sub(r"\{[^}]*\}", "{id}", path) if path else path


def money_fields(body, schema=()):
    """Echo mining (GV-3): money-shaped field names in a resource's own 2xx
    response that the create schema does not declare — evidence-backed
    mass-assign candidates, zero extra requests."""
    if not isinstance(body, dict):
        return []
    declared = set(schema or ())
    out = []
    for k in body:
        if k in declared or not isinstance(body[k], (int, float)):
            continue
        if MONEY_FIELD_RE.search(k) or PCT_FIELD_RE.search(k):
            out.append(k)
    return out


def extract_ids(body):
    """id-shaped string values in a response body (foreign-id detection)."""
    if isinstance(body, dict):
        vals = [body]
        for v in body.values():
            if isinstance(v, list):
                vals.extend(x for x in v if isinstance(x, dict))
    elif isinstance(body, list):
        vals = [x for x in body if isinstance(x, dict)]
    else:
        return []
    out = {v for x in vals
           for k, v in x.items()
           if isinstance(v, str) and (k.endswith("_id") or
                                      ID_VALUE_RE.match(v))}
    for x in vals:
        for v in x.values():
            if isinstance(v, str) and ID_VALUE_RE.match(v):
                out.add(v)
    return sorted(out)


def credited_keys(body):
    """Money-ish keys in a verb-probe response => the verb CREDITED the
    caller (evidence for h_value_replay)."""
    if not isinstance(body, dict):
        return []
    return [k for k, v in body.items()
            if isinstance(v, int) and MONEY_FIELD_RE.search(k)]


# --------------------------------------------------------------- probes ----
def probe_nouns(ex, p, known_paths, phase="technique", budget_guard=None):
    """GET /api/{noun} x len(VALUE_NOUNS); status != 404 => resource fact.
    Returns [{noun, path, status}]. Budget-guard is a callable() -> bool."""
    out = []
    known = {normalize(x).rstrip("/") for x in known_paths or []}
    for noun in VALUE_NOUNS:
        if budget_guard and not budget_guard():
            break
        path = "/api/%s" % noun
        r = ex.request(p, "GET", path, phase=phase, tag="noun-probe")
        if r["status"] == 404:
            continue
        out.append({"noun": noun, "path": path, "status": r["status"],
                    "documented": normalize(path) in known})
    return out


def open_resource(ex, p, path, phase="technique"):
    """POST {} once. Returns dict:
       {kind: 'object'|'async'|'error'|'absent', status, body,
        learned_field} — 'async' hands off to the window driver."""
    r = ex.request(p, "POST", path, body={}, phase=phase,
                   tag="resource-open")
    if r["status"] == 202:
        return {"kind": "async", "status": 202, "body": r["resp_body"],
                "learned_field": None}
    if 200 <= r["status"] < 300:
        return {"kind": "object", "status": r["status"],
                "body": r["resp_body"], "learned_field": None}
    if r["status"] in (400, 401, 403, 422):
        # U3 analogue: learn the create field from the error contract
        from engine.window import field_from_error
        return {"kind": "error", "status": r["status"],
                "body": r["resp_body"],
                "learned_field": field_from_error(r["resp_body"])}
    return {"kind": "absent", "status": r["status"], "body": r["resp_body"],
            "learned_field": None}


def probe_verbs(ex, p, res, oid, known_verbs, phase="technique",
                budget_guard=None, vocab=None):
    """POST /api/{res}/{oid}/{verb} x VERB_VOCAB (minus known).
    non-404/405 => verb fact {verb, status, credited}."""
    out = []
    for verb in (vocab or VERB_VOCAB):
        if verb in known_verbs:
            continue
        if budget_guard and not budget_guard():
            break
        path = "/api/%s/%s/%s" % (res, oid, verb)
        r = ex.request(p, "POST", path, body={}, phase=phase,
                       tag="verb-probe")
        if r["status"] in (404, 405):
            continue
        out.append({"resource": res, "verb": verb, "path": path,
                    "status": r["status"],
                    "credited": bool(credited_keys(r["resp_body"]))})
    return out


def single_use_signature(ex, p, verb_path, phase="technique"):
    """Second identical probe on a claim-family verb: 200-then-409 => the
    endpoint is a single-use check-then-act (race candidate, GV-6).
    Returns {single_use, first, second} — caller supplies first status."""
    r = ex.request(p, "POST", verb_path, body={}, phase=phase,
                   tag="single-use-sig")
    return r["status"]


def probe_subpaths(ex, p, collections, phase="technique", budget_guard=None):
    """GET /api/{res}/{sub} x SUBPATH_NOUNS (<=3 collections).
    2xx => readback fact {path, resource, sub, body}."""
    out = []
    for res in collections[:3]:
        for sub in SUBPATH_NOUNS:
            if budget_guard and not budget_guard():
                break
            path = "/api/%s/%s" % (res, sub)
            r = ex.request(p, "GET", path, phase=phase, tag="subpath-probe")
            if 200 <= r["status"] < 300:
                out.append({"path": path, "resource": res, "sub": sub,
                            "body": r["resp_body"]})
    return out


# ---------------------------------------------------------------- merge ----
def merge(surface, discoveries):
    """Pure: fold discovery facts into the surface dict (deep-copied).
    Discovered actions are shape-identical to doc actions plus
    discovered:True, so every existing consumer (_res_actions, window
    driver, t_state_guard, t_cross_tenant) treats them uniformly."""
    import copy
    s = copy.deepcopy(surface or {})
    disc = s.setdefault("discoveries", {
        "resources": [], "verb_facts": [], "single_use": [],
        "readback_added": [], "undocumented_verbs": [],
        "undocumented_resources": [], "mined_fields": {}})
    graph = s.setdefault("resource_actions", {})

    for res in discoveries.get("resources", []):
        noun, path = res["noun"], res["path"]
        g = graph.setdefault(noun, {"create": None, "actions": [],
                                    "param": None, "param_name": None})
        if g.get("create") is None and \
                res.get("open_kind") in ("object", "error", "async"):
            g["create"] = path
            g["create_schema"] = res.get("create_schema") or {}
            if res.get("open_kind") == "object":
                g["discovered"] = True
            have = {r.get("noun") if isinstance(r, dict) else r
                    for r in disc["undocumented_resources"]}
            if noun not in have and res.get("documented") is False:
                disc["undocumented_resources"].append(
                    {"noun": noun, "path": path,
                     "open_kind": res.get("open_kind"),
                     "open_status": res.get("open_status")})

    for a in discoveries.get("actions", []):
        res, verb, path = a["resource"], a["verb"], a["path"]
        g = graph.setdefault(res, {"create": None, "actions": [],
                                   "param": None, "param_name": None})
        if not any(x.get("verb") == verb and x.get("path") == path
                   for x in g["actions"]):
            g["actions"].append({"verb": verb, "path": path, "method": "POST",
                                 "schema": {}, "schema_unknown": True,
                                 "discovered": True})
        if (res, verb) not in [(d["resource"], d["verb"])
                               for d in disc["undocumented_verbs"]]:
            disc["undocumented_verbs"].append(
                {"resource": res, "verb": verb, "status": a["status"]})

    for vf in discoveries.get("verb_facts", []):
        disc["verb_facts"].append(vf)
    for su in discoveries.get("single_use", []):
        disc["single_use"].append(su)

    for rb in discoveries.get("readback", []):
        if rb["path"] not in (s.get("readback") or []):
            s.setdefault("readback", []).append(rb["path"])
            disc["readback_added"].append(rb["path"])

    for res, fields in (discoveries.get("mined_fields") or {}).items():
        if res in graph:
            merged = set(graph[res].get("mined_fields") or ())
            merged.update(fields)
            graph[res]["mined_fields"] = sorted(merged)
            disc["mined_fields"][res] = sorted(merged)

    # V5 (doc trust): traffic-proven create failures degrade doc trust
    s["doc_suspect"] = discoveries.get("doc_suspect", {})
    return s


def scan_traffic_suspect_docs(ex, max_fails=3):
    """Doc-trust degradation (V5): >= max_fails lawful create attempts
    (tag='create') answered 400/422 on one path => that doc create is
    suspect; consumers should prefer the U3 error contract."""
    path = getattr(ex, "traffic_path", None)
    if not path or not os.path.exists(path):
        return {}
    fails = {}
    with open(path) as fh:
        for line in fh:
            try:
                x = json.loads(line)
            except ValueError:
                continue
            if x.get("tag") == "create" and x.get("status") in (400, 422):
                fails[x["path"]] = fails.get(x["path"], 0) + 1
    return {p: n for p, n in fails.items() if n >= max_fails}
