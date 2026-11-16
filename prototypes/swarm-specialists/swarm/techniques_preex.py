"""PRE-EXPLOITATION technique library (M5) — evidence gathering that competes
with exploits in one utility ranking (Sarraute arXiv:1307.7808: a POMDP mixes
scanning actions with exploit actions; information gathering is not a phase
prefix, it is a cheap action with an expected payoff).

Every technique is a CALDERA-shaped OPERATOR: declared preconditions (what
must exist on the surface graph), effects (what facts it publishes), and a
request cap. None of them record findings — only the exploit + verify
pipeline can. They publish EVIDENCE and, where the evidence confirms a
precondition, HYPOTHESES with raised priors (hypothesis.py remains the only
other hypothesis source; exploit tests, verify confirms).

Lineage (RESEARCH-M5 §2):
  px_object_map    — BOLABuster 2024 step 1 (enumerate objects per account)
  px_authz_matrix  — BOLABuster step 2 (cross-account access matrix);
                     OWASP API Top-10 #1 (BOLA) test; denials are recorded
                     too — the negative control ships with the positive.
  px_param_probe   — Arjun-style differential hidden-parameter mining with
                     TARGET-DERIVED candidates (schema fields + observed
                     response keys first, generic class-hints second).

Target-agnostic contract: techniques consume the SURFACE graph shape only
(resource_actions / readback), never target-specific names.
"""
from statefuzz.executor import Principal

from . import techniques as T

# generic class-hint candidates for hidden-parameter mining (Arjun's spirit:
# small, targeted, derived; the target's own schema fields outrank these)
_PARAM_CLASS_HINTS = ("status", "state", "approved", "role", "owner",
                      "price", "amount", "value", "balance", "credit",
                      "internal", "admin", "override", "discount", "tenant")

_ID_FIELD_HINTS = ("id", "uuid", "guid", "ref", "number", "key")

_DENY = (401, 403, 404)


# --------------------------------------------------------------- helpers --
def _id_from_body(body):
    """Pull the first id-shaped field out of a JSON response body."""
    if not isinstance(body, dict):
        return None
    for k, v in body.items():
        if any(h in k.lower() for h in _ID_FIELD_HINTS) and v is not None \
                and not isinstance(v, (dict, list)):
            return v
    return None


def _write_actions(g):
    return [a for a in g.get("actions", [])
            if a.get("method", "POST") in ("POST", "PUT", "PATCH")]


def _param_candidates(env, g, a):
    """TARGET-DERIVED candidate set (Arjun with provenance): the resource's
    own schema fields and observed response keys first, generic class hints
    second, always excluding fields the schema already declares."""
    known = set()
    for spec in (g.get("create_schema") or {}):
        known.add(spec)
    for spec in (a.get("schema") or {}):
        known.add(spec)
    seen = set(env.notes.get("param_pool") or [])
    derived = [p for p in seen if p not in known]
    generic = [h for h in _PARAM_CLASS_HINTS if h not in known]
    return derived, generic


# ------------------------------------------------------------- operators --
def px_object_map(env, cap=18):
    """Enumerate business objects per principal (BOLABuster step 1).

    Preconditions: >=1 resource with a create verb. Effects: {object_map}
    evidence payload — {resource: {principal: [ids]}}. Cap: ~6+2*resources.
    """
    resources = [r for r, g in (env.surface.get("resource_actions") or
                                {}).items()
                 if g.get("create") and r not in T._AUTH_RESOURCES]
    if not resources or env.remaining() < 8:
        return None, "failure"
    registry = {}
    a = env.register("pxa")
    b = env.register("pxb")
    used = 4                                   # 2 registrations x 2 requests
    for res in resources:
        if used >= cap - 2 or env.remaining() < 4:
            break
        g = env.surface["resource_actions"][res]
        for who, p in (("A", a), ("B", b)):
            r = env.create(p, g)
            used += 1
            oid = _id_from_body(r.get("resp_body")) if r else None
            if oid is not None:
                registry.setdefault(res, {}).setdefault(who, []).append(oid)
    payload = {"object_map": registry, "principals": [a.name, b.name]}
    env.notes["matrix_principals"] = [a.name, b.name]   # matrix needs these
    return payload, ("success" if registry else "failure")


def px_authz_matrix(env, cap=26):
    """Cross-principal access matrix on parameterised object paths
    (BOLABuster step 2, deterministic).

    Preconditions: object_map fact on this run + param paths. Effects:
    {authz_matrix} — per (resource, principal-pair): observed statuses,
    body-shape match, and a verdict {bola-evidence | enforced}. The matrix
    records DENIALS with the same fidelity as grants (negative control).
    """
    omap = (env.notes.get("px_object_map") or {}).get("object_map") or {}
    if not omap or env.remaining() < 10:
        return None, "failure"
    a_name, b_name = env.notes.get("matrix_principals") or (None, None)
    principals = {}
    for name in (a_name, b_name):
        if name and name in env.ex.principals:
            principals[name] = env.ex.principals[name]
    if len(principals) < 2:
        return None, "failure"
    names = sorted(principals)
    pa, pb = principals[names[0]], principals[names[1]]

    rows, used, hits = [], 0, 0
    for res, owners in sorted(omap.items()):
        g = (env.surface.get("resource_actions") or {}).get(res) or {}
        ppath = g.get("param")
        if not ppath or "{" not in ppath or env.remaining() < 4:
            continue
        b_ids = owners.get("B") or []
        a_ids = owners.get("A") or []
        if not b_ids:
            continue
        # the ONE probe that matters: can A read B's object (and the mirror)?
        for victim_owner, victim_ids, attacker in (
                ("B", b_ids[:1], pa), ("A", a_ids[:1], pb)):
            for oid in victim_ids:
                path = ppath.replace("{%s}" % (g.get("param_name") or "id"),
                                     str(oid))
                r = env.ex.request(attacker, "GET", path, phase="preex",
                                   tag="authz-matrix")
                used += 1
                body = r.get("resp_body")
                got_id = _id_from_body(body) if isinstance(body, dict) \
                    else None
                match = (got_id is not None and str(got_id) == str(oid))
                verdict = ("bola-evidence" if r["status"] == 200 and match
                           else "enforced" if r["status"] in _DENY
                           else "inconclusive:%d" % r["status"])
                if verdict == "bola-evidence":
                    hits += 1
                rows.append({"resource": res, "victim_owner": victim_owner,
                             "object_id": str(oid), "attacker":
                                 attacker.name, "path": path,
                             "status": r["status"], "verdict": verdict})
                if used >= cap or env.remaining() < 3:
                    break
            if used >= cap or env.remaining() < 3:
                break
        if used >= cap or env.remaining() < 3:
            break
    payload = {"authz_matrix": rows, "bola_hits": hits}
    return payload, ("success" if rows else "failure")


def px_param_probe(env, cap=16):
    """Hidden-parameter mining on a write action (Arjun-style differential).

    Preconditions: a param object the probe principal owns + a write action.
    Method: control request (schema-true body), then ONE candidate per
    request; a param 'exists' when the response differs from the control
    (status or body length) AND the control was a clean 2xx. Effects:
    {hidden_params} with per-candidate evidence. Capped hard: 1 control +
    <=12 candidates + 1 re-confirm on the strongest hit.
    """
    if env.remaining() < 14:
        return None, "failure"
    for res, g in sorted((env.surface.get("resource_actions") or
                          {}).items()):
        if res in T._AUTH_RESOURCES or not g.get("create"):
            continue
        owners = (env.notes.get("object_map") or {}).get(res) or {}
        p = None
        for who in sorted(owners):
            cand = (env.notes.get("matrix_principals") or (None, None))
            cand_name = cand[0] if who == "A" else cand[1]
            p = env.ex.principals.get(cand_name or "")
            if p is not None:
                break
        if p is None:
            p = env.register("pxq")
        r_create = env.create(p, g)
        if not r_create:
            continue
        oid = _id_from_body(r_create.get("resp_body"))
        writes = _write_actions(g)
        if oid is None or not writes or env.remaining() < 10:
            continue
        a = writes[0]
        path = a["path"].replace("{%s}" % (g.get("param_name") or "id"),
                                 str(oid))
        base = T._action_body(a)
        ctrl = env.ex.request(p, a["method"], path, body=base,
                              phase="preex", tag="param-control")
        if not (200 <= ctrl["status"] < 300):
            continue
        ctrl_key = (ctrl["status"],
                    len(json_dumps(ctrl.get("resp_body"))))
        derived, generic = _param_candidates(env, g, a)
        cands = (derived + [c for c in generic if c not in derived])[:12]
        found = []
        for cand in cands:
            if env.remaining() < 2:
                break
            body = dict(base)
            body[cand] = _probe_value(cand)
            r = env.ex.request(p, a["method"], path, body=body,
                               phase="preex", tag="param-probe")
            r_key = (r["status"], len(json_dumps(r.get("resp_body"))))
            if r_key != ctrl_key:
                found.append({"param": cand, "source":
                              ("schema-observed" if cand in derived
                               else "class-hint"),
                              "status": r["status"],
                              "control_status": ctrl["status"]})
        payload = {"hidden_params": found, "endpoint": path,
                   "resource": res, "control": {"status": ctrl["status"],
                                                "body_len": ctrl_key[1]}}
        return payload, ("success" if found else "failure")
    return None, "failure"


def _probe_value(name):
    """A value that is plausible-but-inert; the probe tests ACCEPTANCE
    (differential), not impact — impact is h_mass_assign's job."""
    if any(h in name for h in ("price", "amount", "value", "balance",
                               "credit", "discount")):
        return 1
    if any(h in name for h in ("status", "state", "approved")):
        return "approved"
    return "px-probe"


def json_dumps(obj):
    import json
    return json.dumps(obj, sort_keys=True, default=str)


def traffic_keys(traffic_path, cap=64):
    """Field-name keys observed on the WIRE so far (response bodies of every
    exchange the run has already made). This is the target-derived candidate
    pool for hidden-parameter mining: the target's own vocabulary outranks
    any generic list (RESEARCH-M5 §2, Arjun-with-provenance)."""
    import json
    import os
    pool = set()
    if not traffic_path or not os.path.exists(traffic_path):
        return []
    try:
        with open(traffic_path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                rb = rec.get("resp_body")
                if isinstance(rb, dict):
                    _walk_keys(rb, pool, 0)
    except OSError:
        return []
    return sorted(pool)[:cap]


def _walk_keys(obj, acc, depth):
    if depth > 2 or not isinstance(obj, dict):
        return
    import re
    for k, v in obj.items():
        if isinstance(k, str) and re.match(r"^[a-z][a-z0-9_]{2,40}$", k) \
                and k not in _STOP_KEYS:
            acc.add(k)
        if isinstance(v, (dict, list)):
            for item in (v if isinstance(v, list) else [v]):
                if isinstance(item, dict):
                    _walk_keys(item, acc, depth + 1)


_STOP_KEYS = {"error", "status", "paths", "info", "openapi", "resources",
              "service", "summary", "requestbody", "schema", "properties",
              "type", "required", "name", "parameters", "version", "title",
              "raw", "token", "password", "username", "policy_denied",
              "rule", "resp_body"}


# ------------------------------------------------------------ hypothesis --
def hypotheses_from(payload):
    """Evidence-raised hypotheses (Sarraute's mixing): only where the matrix
    actually saw a cross-principal 200, or a hidden param was accepted.
    Returns [(tag, prior, evidence, summary)]."""
    out = []
    if payload.get("authz_matrix"):
        hits = [r for r in payload["authz_matrix"]
                if r["verdict"] == "bola-evidence"]
        for h in hits[:2]:
            out.append(("h_cross_tenant", 0.85,
                        ["authz-matrix: %s -> %d with owner-matched body "
                         "(attacker=%s, victim_owner=%s)"
                         % (h["path"], h["status"], h["attacker"],
                            h["victim_owner"])],
                        "Authz matrix observed cross-principal object read "
                        "succeed with owner-matched body"))
    if payload.get("hidden_params"):
        fps = [p["param"] for p in payload["hidden_params"]]
        out.append(("h_mass_assign", 0.75,
                    ["param-probe: differential acceptance on %s"
                     % ",".join(fps)],
                    "Hidden write-side parameters accepted on a business "
                    "object (may override pricing/entitlements)"))
    return out


# ----------------------------------------------------------------- run ----
def run(env, budget_cap=70):
    """The pre-ex ladder, cheapest-information-first. Returns
    {technique: outcome} + the payload each produced (env.notes carries the
    cross-technique state: object map feeds the matrix). Two consecutive
    dead arms stop the ladder — dead-end probing buys no information
    (Sarraute: every action must earn its requests)."""
    outcomes, payloads = {}, {}
    dead = 0
    order = (("px_object_map", px_object_map),
             ("px_authz_matrix", px_authz_matrix),
             ("px_param_probe", px_param_probe))
    for name, fn in order:
        if env.remaining() < 12 or dead >= 2:
            break
        payload, outcome = fn(env, cap=min(budget_cap, env.remaining()))
        outcomes[name] = outcome
        dead = dead + 1 if outcome == "failure" else 0
        if payload:
            payloads[name] = payload
            env.notes[name] = payload
    return outcomes, payloads
