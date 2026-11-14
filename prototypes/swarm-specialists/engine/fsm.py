"""engine/fsm.py — M3 (G3c): the live-induced transition table.

The v1 FSM path was a scripted walk (dvlba's checkout lifecycle). The stale-
doc class hides its lifecycle in UNDOCUMENTED verbs: Freightlane's shipment
lifecycle (booked -> picked_up -> delivered -> settled) is invisible to the
openapi document, and GV-8 lives exactly in the gap between the induced
order and what the guards enforce.

Free FSM oracles used here (each grounded, no guessing):
  * 409-gating  — a transition verb answered 409 from a state: the resource
                  HAS order guards; the row names the constraint.
  * state echo  — a GET on the object whose body carries a state-shaped
                  field (status/state/stage) names the states themselves.

induce() walks LIFECYCLE_NOUNS (+ already-discovered schemaless actions)
across the states of ONE object: 2xx advances the walk (and the re-probe at
the next state IS the replay probe — a verb answered 2xx and later 409 is a
guarded one-shot; answered 2xx twice is a replayable transition). MONEY
verbs are deliberately excluded from the walk: induction must never move
value (the band-D discipline) — terminal verbs are invoked only by the
dedicated follow-through arms with wallet baselines (techniques.t_state_skip).

Layering: spine module — must not import the swarm. Every request goes
through the shared executor (budget/STOP/traffic provenance).
"""
STATE_KEYS = ("status", "state", "stage")

# lifecycle intermediate nouns: the order-carrying verbs no pricing doc
# ever lists. Bounded: the walk caps probes per object (max_probes).
LIFECYCLE_NOUNS = ("pickup", "deliver", "ship", "start", "dispatch",
                   "process", "transit", "arrive", "prepare", "finalize")

# verbs whose name claims a terminal / successor transition
TERMINAL_VERBS = ("settle", "complete", "confirm", "fulfill", "approve",
                  "capture", "close", "terminate")


def state_echo(body):
    """A state-shaped value in an object read-back ('booked', 'settled'...)."""
    if not isinstance(body, dict):
        return None
    for k in STATE_KEYS:
        v = body.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def read_state(ex, p, g, oid, phase):
    """State echo via the resource's param GET (1 request; None if absent)."""
    param = g.get("param")
    if not param or "{" not in param:
        return None
    r = ex.request(p, "GET",
                   param.replace("{%s}" % (g.get("param_name") or "id"),
                                 oid),
                   phase=phase, tag="fsm-state-read")
    if r["status"] in (404, 405):
        return None
    return state_echo(r["resp_body"])


def induce(ex, p, res, g, oid, known_verbs, discovered_verbs,
           phase="technique", budget_guard=None, max_probes=16,
           max_gate_rows=2, exclude=()):
    """Walk the lifecycle of ONE object; return the induced table.

    Candidates: LIFECYCLE_NOUNS + the resource's discovered schemaless
    actions ({} is the lawful probe there), minus documented verbs, minus
    terminal verbs (the follow-through arms own those, with wallet
    baselines), minus the caller's `exclude` list (CREDITED verbs —
    induction must never move value; the band-D discipline).
    Row grammar: {verb, state_before, status, state_after, gated}.
      gated=True  -> 409 at that state: an order constraint (evidence).
      2xx + advance -> the walk continues at the new state; re-probing the
      same verb there is the built-in replay check.
    Returns {"rows": [...], "state0": str|None, "probes": int,
             "verbs_absent": n}.
    """
    known = set(known_verbs or ())
    banned = set(exclude or ()) | set(TERMINAL_VERBS)
    pool = [v for v in LIFECYCLE_NOUNS
            if v not in known and v not in banned]
    for v in discovered_verbs or ():
        if v not in pool and v not in known and v not in banned:
            pool.append(v)
    rows, probes, absent = [], 0, 0
    gate_counts = {}
    state = read_state(ex, p, g, oid, phase)
    state0 = state
    progressed = True
    while pool and progressed and probes < max_probes:
        if budget_guard is not None and not budget_guard():
            break
        progressed = False
        for verb in list(pool):
            if probes >= max_probes or (budget_guard is not None and
                                        not budget_guard()):
                break
            probes += 1
            path = "/api/%s/%s/%s" % (res, oid, verb)
            r = ex.request(p, "POST", path, body={}, phase=phase,
                           tag="fsm-walk")
            if r["status"] in (404, 405):
                pool.remove(verb)
                absent += 1
                continue
            if r["status"] == 409:
                gate_counts[verb] = gate_counts.get(verb, 0) + 1
                rows.append({"verb": verb, "state_before": state,
                             "status": 409, "state_after": None,
                             "gated": True})
                if gate_counts[verb] >= max_gate_rows:
                    pool.remove(verb)       # constraint evidenced; enough
                continue
            after = read_state(ex, p, g, oid, phase)
            advanced = after is not None and after != state
            rows.append({"verb": verb, "state_before": state,
                         "status": r["status"], "state_after": after,
                         "gated": False})
            if 200 <= r["status"] < 300 and advanced:
                state = after
                progressed = True
                break                       # restart pool at the new state
            pool.remove(verb)               # no-op 2xx / error: exhausted
    return {"rows": rows, "state0": state0, "probes": probes,
            "verbs_absent": absent}


def gated_rows(table):
    """409 rows — proof the resource orders its transitions."""
    return [r for r in table.get("rows", []) if r.get("gated")]


def replayable_rows(table):
    """Verbs answered 2xx at two different states with a state change both
    times — a transition the resource failed to make one-shot (I1 shape).
    The walk itself is the replay; no extra requests."""
    by_verb = {}
    for r in table.get("rows", []):
        if 200 <= (r.get("status") or 0) < 300 and \
                r.get("state_after") not in (None, r.get("state_before")):
            by_verb.setdefault(r["verb"], []).append(r)
    return {v: rs for v, rs in by_verb.items() if len(rs) >= 2}
