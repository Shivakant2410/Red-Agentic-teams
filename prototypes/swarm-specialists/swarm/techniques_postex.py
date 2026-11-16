"""POST-EXPLOITATION technique library (M5) — what a real operator does AFTER
a primitive verifies: measure how far it reaches, whether it persists, and
what else the same foothold touches. ATT&CK's post-ex tactics (Credential
Access / Lateral Movement / persistence) translated to the web tier, where
"credentials" = sessions/tokens and "lateral movement" = the same primitive
against sibling objects/principals.

Lineage (RESEARCH-M5 §2):
  px_amplify        — XBOW's documented variant-analysis play ("hidden
                      endpoints following the same pattern") + the
                      BloodHound/Elmiger reachability-count math: impact of
                      one primitive = how many victims it actually reaches,
                      each with a MEASURED delta, never asserted.
  px_persist_replay — PentestGPT's post-ex phase (replayability/persistence
                      of a primitive); doubles as double-credit detection.
  px_scope_traverse — capability footprint: with the foothold's session,
                      enumerate which documented endpoints answer 2xx —
                      the "what else can this token do" map every report
                      needs and scanners never produce.

Discipline inherited from ACCESS: post-ex fires only on VERIFIED work —
candidate findings never get amplification budget. All techniques are
cost-capped and record their own outcomes for the bandit (E1).
"""
import re

from . import techniques as T
from .techniques_preex import _id_from_body

_EP_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE)\s+"
                    r"(/\S+?)(?:\s+\(|$)")


def _winning_body(fd):
    """The EXACT winning request body when the finding recorded one
    (evidence[*].injected). If the primitive's demonstrated worst case used
    the NEGATIVE operator, replay THAT variant — amplification measures the
    primitive's maximum PROVEN reach, and the negative variant is already
    exploit-phase evidence, not a new guess."""
    inj = None
    for ev in fd.get("evidence") or []:
        if isinstance(ev, dict) and isinstance(ev.get("injected"), dict):
            inj = dict(ev["injected"])
            if "NEGATIVE" in (fd.get("operators") or []) and \
                    isinstance(ev.get("candidate_field"), str) and \
                    isinstance(ev.get("negative_probe_credit"), int):
                inj[ev["candidate_field"]] = \
                    -ev["negative_probe_credit"]
            break
    return inj


def _op_from_finding(fd, surface):
    """Recover the winning (method, path_template, body, resource, graph)
    from a finding's endpoint string ("POST /api/x/{id}/verb (label)").

    v2 (M5): action matching is by METHOD + tail segment against the surface
    graph, so templated, concrete and labelled endpoint strings all resolve;
    the recorded winning body (evidence[*].injected) outranks any
    reconstruction; unmatched (hidden-verb / collection) primitives keep
    their finding path — an empty body IS the lawful probe (M2/GV-2 shape)."""
    m = _EP_RE.match(str(fd.get("endpoint", "")))
    if not m:
        return None
    method, path = m.group(1), m.group(2)
    tail = path.rstrip("/").split("/")[-1]
    paramted = "{" in path
    inj = _winning_body(fd)
    for res, g in (surface.get("resource_actions") or {}).items():
        for a in g.get("actions", []):
            ap = a.get("path") or ""
            if a.get("method", "POST") != method:
                continue
            atail = ap.rstrip("/").split("/")[-1]
            if atail == tail and ("{" in ap) == paramted:
                body = inj if inj is not None else _lawful_body(a)
                return method, ap, body, res, g
    # hidden verb / collection primitive: keep the finding's path
    return method, path, inj if inj is not None else {}, None, None


def _lawful_body(a):
    ints = T._int_fields(a.get("schema"))
    if ints:
        return {ints[0]: 1}
    return T._action_body(a)


def _sub(path, oid):
    return re.sub(r"\{[^}]+\}", str(oid), path)


def px_amplify(env, fd, surface, cap=30):
    """Replay the verified primitive against fresh victims' objects; count
    reach and aggregate the measured value deltas (reachability math:
    impact = count of victims actually reached x measured delta)."""
    op = _op_from_finding(fd, surface)
    if op is None or env.remaining() < 20:
        return None, "failure"
    method, path, body, op_res, op_g = op
    # the money read-back must be probed with an AUTHENTICATED principal:
    # an anon 401 says nothing about whether a balance path exists (M5)
    probe = env.register("pxw")
    if env.wallet(probe) is None and env.cache.get("balance_path") is None:
        return None, "failure"
    victims = []
    for i in range(3):
        if env.remaining() < 8:
            break
        made = False
        # victims own objects of the PRIMITIVE's resource when the op named
        # one; otherwise the first documented create-resource
        res_order = ([op_res] if op_res and op_res in
                     (surface.get("resource_actions") or {})
                     else sorted(surface.get("resource_actions") or {}))
        for res in res_order:
            g = surface["resource_actions"][res]
            if res in T._AUTH_RESOURCES or not g.get("create") or \
                    env.remaining() < 7:
                continue
            p = env.register("pxv%d" % i)
            r = env.create(p, g)
            oid = _id_from_body(r.get("resp_body")) if r else None
            if oid is not None:
                victims.append((p, res, oid))
                made = True
                break
        if not made:
            break
    if not victims:
        return None, "failure"
    rows, reached, total = [], 0, 0
    for p, res, oid in victims:
        if env.remaining() < 4:
            break
        before = env.wallet(p)
        r = env.ex.request(p, method, _sub(path, oid),
                           body=body if body else None,
                           phase="postex", tag="amplify")
        after = env.wallet(p)
        delta = (after - before) if (isinstance(before, int) and
                                     isinstance(after, int)) else 0
        exposed = 0
        rb = r.get("resp_body")
        if isinstance(rb, dict):
            for v in rb.values():
                if isinstance(v, list):
                    exposed += len(v)
        elif isinstance(rb, list):
            exposed = len(rb)
        rows.append({"victim": p.name, "resource": res,
                     "object_id": str(oid), "status": r["status"],
                     "delta_cents": delta, "records_exposed": exposed})
        if r["status"] < 300 or delta != 0 or exposed:
            reached += 1
            total += abs(delta)
    payload = {"amplification": {"victims_probed": len(rows),
                                 "victims_reached": reached,
                                 "aggregate_delta_cents": total,
                                 "variant": ("negative-probe"
                                             if body and _is_negative(fd, body)
                                             else "recorded"),
                                 "rows": rows,
                                 "primitive": {"method": method,
                                               "path": path}}}
    return payload, ("success" if reached else "failure")


def _is_negative(fd, body):
    """True when the replayed body is the finding's NEGATIVE variant."""
    for ev in fd.get("evidence") or []:
        if isinstance(ev, dict) and \
                ev.get("candidate_field") in (body or {}) and \
                isinstance(ev.get("negative_probe_credit"), int):
            return body[ev["candidate_field"]] == \
                -ev["negative_probe_credit"]
    return False


def px_persist_replay(env, fd, surface, cap=12):
    """Repeatability of the primitive on a SELF-owned object: replay x2,
    measure the wallet after each. A repeatable accrual (same-sign non-zero
    delta on the second replay — credit OR underpricing) is the
    persistence/double-credit signal."""
    op = _op_from_finding(fd, surface)
    if op is None or env.remaining() < 18:
        return None, "failure"
    method, path, body, res, g = op
    if g is None or not g.get("create"):
        # hidden-verb primitive: fall back to the first documented resource
        # with a create, so the replay still fires against a SELF-owned object
        for r2, g2 in sorted((surface.get("resource_actions") or {}).items()):
            if r2 not in T._AUTH_RESOURCES and g2.get("create"):
                res, g = r2, g2
                break
    p = env.register("pxr")
    if env.wallet(p) is None or g is None or not g.get("create") or \
            env.remaining() < 10:
        return None, "failure"
    r_create = env.create(p, g)
    oid = _id_from_body(r_create.get("resp_body")) if r_create else None
    if oid is None:
        return None, "failure"
    path = _sub(path, oid)
    before = env.wallet(p)
    deltas = []
    for i in range(2):
        if env.remaining() < 4:
            break
        r = env.ex.request(p, method, path,
                           body=body if body else None,
                           phase="postex", tag="persist-replay")
        after = env.wallet(p) if env.remaining() >= 2 else None
        deltas.append({"status": r["status"],
                       "delta_cents": ((after - before)
                                       if (isinstance(before, int) and
                                           isinstance(after, int))
                                       else None)})
        if after is not None:
            before = after
    if not deltas:
        return None, "failure"
    ds = [d.get("delta_cents") for d in deltas]
    repeatable = (len(ds) == 2 and all(d for d in ds) and
                  (all(d > 0 for d in ds) or all(d < 0 for d in ds)))
    payload = {"persistence": {"primitive": {"method": method,
                                             "path": path},
                               "replays": deltas,
                               "repeatable": repeatable}}
    return payload, "success"


def px_scope_traverse(env, principal, surface, cap=14):
    """Capability footprint of a foothold session: GET every documented
    readback + param read; record which answer 2xx (what else this token
    can touch) vs denied."""
    targets = [t for t in (surface.get("readback") or []) if "{" not in t]
    for res, g in sorted((surface.get("resource_actions") or {}).items()):
        if g.get("param"):
            targets.append(g["param"])
    targets = targets[:max(0, min(cap, env.remaining() - 2))]
    if not targets or principal is None or env.remaining() < len(targets) \
            + 2:
        return None, "failure"
    accessible = []
    for t in targets:
        r = env.ex.request(principal, "GET", t, phase="postex",
                           tag="scope-traverse")
        if 200 <= r["status"] < 300:
            accessible.append(t)
    payload = {"capability_footprint": {"session": principal.name,
                                        "probed": len(targets),
                                        "accessible": accessible,
                                        "denied": len(targets) -
                                        len(accessible)}}
    return payload, ("success" if accessible else "failure")


# ----------------------------------------------------------------- run ----
def run(env, findings, cap=48):
    """The post-ex ladder over verified findings (ACCESS discipline: never
    on candidates). Amplify tries verified primitives in board order (up to
    3) until one actually REACHES victims with a measured effect — the
    operator amplifies the foothold that pays, and reports the ones that
    did not. Returns {technique: outcome} + payloads."""
    outcomes, payloads = {}, {}
    if not findings or env.remaining() < 16:
        return outcomes, payloads
    fds = [(f.get("finding") or f) for f in findings[:3]]
    best = None
    for fd in fds:
        if env.remaining() < 14:
            break
        pay, oc = px_amplify(env, fd, env.surface,
                             cap=min(cap, env.remaining()))
        if pay is not None:
            amp = pay.get("amplification") or {}
            if best is None or abs(amp.get("aggregate_delta_cents") or 0) \
                    > abs((best[0].get("amplification") or {})
                          .get("aggregate_delta_cents") or 0):
                best = (pay, fd)
        if oc == "success" and pay and \
                (pay.get("amplification") or {}).get(
                    "aggregate_delta_cents"):
            break
    if best is not None:
        payloads["px_amplify"] = best[0]
        outcomes["px_amplify"] = "success" if \
            (best[0]["amplification"]["victims_reached"] and
             best[0]["amplification"]["aggregate_delta_cents"]) \
            else "failure"
    else:
        outcomes["px_amplify"] = "failure"
    fd = (best[1] if best else fds[0]) if fds else None
    if fd is not None and env.remaining() >= 18:
        pay, oc = px_persist_replay(env, fd, env.surface)
        outcomes["px_persist_replay"] = oc
        if pay:
            payloads["px_persist_replay"] = pay
    if env.remaining() >= 8:
        p = env.register("pxs") if env.remaining() >= 4 else None
        if p is not None:
            pay, oc = px_scope_traverse(env, p, env.surface,
                                        cap=min(14, env.remaining()))
            outcomes["px_scope_traverse"] = oc
            if pay:
                payloads["px_scope_traverse"] = pay
    return outcomes, payloads
