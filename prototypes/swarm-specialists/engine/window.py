"""engine/window.py — M1 (G1): the ledger as ENGINE.

Two halves:

1. Shape observation (`classify_async`, `field_from_error`): turn raw HTTP
   exchanges into deferred-effect shapes. A 202 whose body carries an
   event-path-shaped string (any value starting with "/") is an ASYNC SEAM —
   a state change the target promises to perform later. That is exactly the
   surface fact the Freightlane run starved on: the payout seam was never
   observed because nothing aimed at it (GAP-PROOF GV-4/GV-5,
   "gate-starved"), and when the ledger was fed by hand it caught both
   violations in 34 requests (run_ledger_probe.py).

2. The WindowDriver: interleaves the deferred window INTO the run instead of
   waiting for end-of-run reconciliation. Per live marker it
     a. polls the event path until the worker settles;
     b. probes the cancel-family verbs after settle (GV-5 shape: refund
        while the external transfer stands);
     c. once per run, opens a FRESH seam under its own control, drains the
        wallet inside the window with a calibrated lawful spend, and checks
        the settle against a sub-zero balance (GV-4 shape: settle debits
        without a balance re-check);
     d. resolves each marker in the ledger from wallet read-backs
        (confirmed on demonstrated violation, refuted when the expectation
        held, inconclusive when the window never settled) — and (G1c) the
        ledger marker state is what decides which operator fires next.

Layering: this module is the spine — it must not import the swarm. Wallet
discovery and the calibrated drain therefore re-implement ~30 lines of
surface-driven logic (the Env.wallet / richness contracts) against the same
surface dict, and CANCEL_VERBS mirrors swarm.techniques' verb family.
"""
import math
import re
import time

MONEY_HINTS = ("balance", "credit", "wallet")
CANCEL_VERBS = ("cancel", "revoke", "close", "terminate")

# Validation-error phrases that name a missing/invalid field — used to learn
# a create contract when the surface has no schema (U3 analogue for seams).
_FIELD_PAT = re.compile(
    r"([a-z][a-z0-9_]{1,40})\s*"
    r"(?:out of range|must be|is required|required|missing|invalid)", re.I)
_MONEY_FIELD = re.compile(r"(amount|price|total|balance|cents|value|cost)",
                          re.I)


# ----------------------------------------------------------- shape layer --
def event_path_of(body):
    """The first string value that looks like a callback/event path."""
    if not isinstance(body, dict):
        return None
    for v in body.values():
        if isinstance(v, str) and v.startswith("/") and len(v) > 1:
            return v
    return None


def object_id_of(body):
    if not isinstance(body, dict):
        return None
    for k, v in body.items():
        if k.endswith("_id") and isinstance(v, str):
            return v
    return None


def classify_async(exchange):
    """Async-accepted shape -> marker shape dict; anything else -> None.

    A seam requires ALL of: status 202 (accepted-for-later), an event path
    in the body, and a truthy object id. The amount comes from the REQUEST
    body (202 bodies acknowledge; they rarely restate the amount).
    """
    rb = exchange.get("resp_body")
    if exchange.get("status") != 202:
        return None
    ev = event_path_of(rb)
    oid = object_id_of(rb)
    if not ev or not oid:
        return None
    req = exchange.get("req_body") or {}
    amount, amount_field = None, None
    if isinstance(req, dict):
        for k, v in req.items():
            if isinstance(v, int) and not isinstance(v, bool) and \
                    _MONEY_FIELD.search(k):
                amount, amount_field = v, k
                break
    path = exchange.get("path") or ""
    parts = [s for s in path.strip("/").split("/") if s]
    resource = parts[1] if len(parts) > 1 else (parts[0] if parts else "")
    return {"event_path": ev, "create_path": path, "resource": resource,
            "object_id": oid, "amount": amount, "amount_field": amount_field,
            "principal": exchange.get("principal")}


def field_from_error(body):
    """Extract the field name a validation error names, money-flavoured
    first. Grounded U3-style learning: the error document IS the schema."""
    if not isinstance(body, dict):
        return None
    text = " ".join(str(v) for v in body.values() if isinstance(v, str))
    best, fallback = None, None
    for m in _FIELD_PAT.finditer(text):
        name = m.group(1).lower()
        if _MONEY_FIELD.search(name):
            best = best or name
        fallback = fallback or name
    return best or fallback


# ------------------------------------------------------------- driver -----
class WindowDriver:
    """Drives live ledger markers through their deferred windows.

    Constructed with (ledger, executor, surface, anon, phase). Every wallet
    read and window action goes through the shared executor, so budget,
    STOP kill-file and traffic provenance apply automatically. Markers are
    grounded ledger entries — the driver is the mutation-selection consumer
    G1(c) asks for: ledger marker state decides which operator (poll /
    cancel / drain) fires next and against which object.
    """

    def __init__(self, ledger, ex, surface, anon=None, phase="window",
                 state=None):
        self.ledger = ledger
        self.ex = ex
        self.surface = surface or {}
        self.anon = anon
        self.phase = phase
        self._wspec = None
        self._seq_pos = 0                 # traffic-scan offset (auto-marking)
        # once-per-run flags live in `state` (caller-owned dict) so they
        # survive across dispatches of a fresh driver instance
        self.state = state if state is not None else {}
        self.drain_attempted = bool(self.state.get("drain_attempted"))

    # ------------------------------------------------------- primitives --
    def _principal(self, name):
        return self.ex.principals.get(name or "")

    def fresh_principal(self, nick):
        """Register/login a fresh identity (per-probe principal discipline,
        D7). Returns the Principal or None."""
        if self.anon is None:
            return None
        name = "%s-%s-%d" % (nick, self.ex.count,
                             int(time.time() * 1000) % 10 ** 6)
        self.ex.request(self.anon, "POST", "/api/register",
                        body={"username": name, "password": "pw-" + name},
                        phase=self.phase, tag="bootstrap")
        r = self.ex.request(self.anon, "POST", "/api/login",
                            body={"username": name, "password": "pw-" + name},
                            phase=self.phase, tag="bootstrap")
        from statefuzz.executor import Principal
        p = Principal(name, token=(r["resp_body"] or {}).get("token"))
        self.ex.principals[name] = p
        return p

    def _wallet_spec(self, p):
        if self._wspec:
            return self._wspec
        self._wspec = (None, None)
        for path in self.surface.get("readback", []) or []:
            if "{" in path:
                continue
            r = self.ex.request(p, "GET", path, phase=self.phase,
                                tag="balance-probe")
            body = r["resp_body"]
            if isinstance(body, dict):
                for k, v in body.items():
                    if isinstance(v, int) and \
                            any(h in k.lower() for h in MONEY_HINTS):
                        self._wspec = (path, k)
                        return self._wspec
        return self._wspec

    def wallet(self, p):
        path, field = self._wallet_spec(p)
        if not path:
            return None
        r = self.ex.request(p, "GET", path, phase=self.phase, tag="wallet")
        v = r["resp_body"]
        return v.get(field) if isinstance(v, dict) else None

    def _create(self, p, create_path, schema, overrides=None):
        """Lawful create with the size ladder (Env.create contract)."""
        body = {}
        for f, spec in (schema or {}).items():
            if isinstance(spec, dict) and spec.get("enum"):
                body[f] = spec["enum"][0]
            elif isinstance(spec, dict) and spec.get("type") == "integer":
                body[f] = max(2, spec.get("minimum", 1) or 1)
            elif isinstance(spec, dict) and spec.get("type") == "string":
                body[f] = "window"
        body.update(overrides or {})
        for mult in (1, 5, 25):
            attempt = dict(body)
            for f, spec in (schema or {}).items():
                if isinstance(spec, dict) and spec.get("type") == "integer" \
                        and f not in (overrides or {}):
                    attempt[f] = body[f] * mult
            r = self.ex.request(p, "POST", create_path, body=attempt,
                                phase=self.phase, tag="create")
            if 200 <= r["status"] < 300:
                return r
            if r["status"] not in (400, 422):
                return None
        return None

    def _int_field_of(self, create_path):
        for res, g in (self.surface.get("resource_actions") or {}).items():
            if g.get("create") == create_path:
                schema = g.get("create_schema") or {}
                for f, s in schema.items():
                    if isinstance(s, dict) and s.get("type") == "integer":
                        return f
        return None

    # ---------------------------------------------------- marker registry --
    def scan_traffic(self):
        """G1(a): NEW unmarked async shapes from the shared traffic
        transcript. This is what makes markers auto-registered from
        202/event shapes wherever they come from — any technique's 202, not
        only the seam probe's. The CALLER grounds them (publishes the
        observation fact, then open_from_shape with its id)."""
        import json
        import os
        out = []
        path = getattr(self.ex, "traffic_path", None)
        if not path or not os.path.exists(path):
            return out
        with open(path) as fh:
            for line in fh:
                try:
                    x = json.loads(line)
                except ValueError:
                    continue
                seq = x.get("seq", 0)
                if seq <= self._seq_pos:
                    continue
                self._seq_pos = seq
                if x.get("phase") == "verify":
                    # verification re-executions are not discoveries: their
                    # windows are already consumed by the verifier, and
                    # driving them adds requests, not information
                    continue
                shape = classify_async(x)
                if shape:
                    out.append(shape)
        return out

    def open_from_shape(self, shape, derived_from, source):
        """Register a marker unless its event path is already marked."""
        if not shape.get("amount"):        # expectation needs an amount
            return None
        for e in self.ledger.markers():
            if (e.get("marker") or {}).get("event_path") == \
                    shape["event_path"]:
                return e
        return self.ledger.mark(source, shape, derived_from)

    # --------------------------------------------------- G1(b): the window --
    def drive_pending(self, grounding=None, max_markers=4):
        """Drive every registered marker; then, once per run, open ONE fresh
        drained window (GV-4) under the driver's own control. Returns the
        list of finding dicts (may be empty)."""
        findings = []
        for marker in self.ledger.markers(state="registered")[:max_markers]:
            findings += self.drive_one(marker)
        if not self.drain_attempted and grounding and \
                any(m["marker"].get("create_path") and
                    m["marker"].get("amount_field")
                    for m in self.ledger.markers()):
            findings += self._drain_window(grounding)
        return findings

    def drive_one(self, marker):
        """Poll one marker's window to settle, then cancel-after-settle.
        The marker's ledger entry is resolved here: confirmed on a
        demonstrated violation, refuted when the expectation held,
        inconclusive when the window never settled (honest vocabulary)."""
        mk = marker["marker"]
        if mk.get("state") != "registered":
            return []
        p = self._principal(mk.get("principal"))
        if p is None:
            self._resolve(marker, "inconclusive",
                          {"note": "marker principal no longer registered"})
            return []
        amt = mk.get("amount") or 0
        ev = [{"step": "baseline", "wallet": mk.get("baseline")}]

        settled = self._poll(mk["event_path"], p, ev)
        if not settled:
            self._resolve(marker, "inconclusive", {
                "note": "event never left pending within ttl",
                "wallet_trace": ev})
            return []

        finding = self._cancel_after_settle(marker, p, amt, ev)
        if finding:
            self._resolve(marker, "confirmed", {
                "note": "violation: %s" % finding["id"],
                "wallet_trace": ev}, finding_ids=[finding["id"]])
        else:
            self._resolve(marker, "refuted", {
                "note": "expectation held: settle debited exactly once, "
                        "cancel (if any) did not re-credit",
                "wallet_trace": ev})
        return [finding] if finding else []

    # ------------------------------------------------------------ actions --
    def _poll(self, event_path, p, ev, timeout=4.0):
        deadline = time.time() + timeout
        polls = 0
        while time.time() < deadline and polls < 14:
            r = self.ex.request(p, "GET", event_path, phase=self.phase,
                                tag="event-poll")
            polls += 1
            st = (r["resp_body"] or {}).get("status") \
                if isinstance(r["resp_body"], dict) else None
            ev.append({"step": "poll", "status": st})
            if st not in (None, "pending"):
                return st
            time.sleep(0.2)
        return None

    def _cancel_after_settle(self, marker, p, amt, ev):
        mk = marker["marker"]
        res, oid = mk.get("resource"), mk.get("object_id")
        w_pre = self.wallet(p)
        ev.append({"step": "post-settle-wallet", "wallet": w_pre})
        for verb in CANCEL_VERBS:
            path = "/api/%s/%s/%s" % (res, oid, verb)
            r = self.ex.request(p, "POST", path, body={}, phase=self.phase,
                                tag="cancel-after-settle")
            if r["status"] in (404, 405):
                continue                     # verb absent: keep probing
            w_post = self.wallet(p)
            refund = (w_post - w_pre) if None not in (w_post, w_pre) else None
            ev.append({"step": "cancel", "verb": verb, "status": r["status"],
                       "refund": refund, "wallet": w_post})
            if 200 <= r["status"] < 300 and refund is not None and \
                    amt and refund >= amt:
                mk["actions_done"].append("cancel-after-settle")
                return self._finding(
                    "FW-SETTLED-CANCEL",
                    "Payout cancel accepted after settlement: the balance is "
                    "refunded while the external transfer stands (net "
                    "position restored, value delivered)",
                    "critical", "I1", ["SKIP"],
                    "POST /api/%s/{id}/cancel" % res,
                    [{"payout": oid, "amount": amt,
                      "settled_status": mk.get("settled_status"),
                      "post_settle_wallet": w_pre, "cancel_credit": refund,
                      "event": mk["event_path"], "resource": res,
                      "create_path": mk.get("create_path"),
                      "amount_field": mk.get("amount_field")}],
                    ["any account", "own settled payout"],
                    ["receive the external payout AND keep the balance"])
            return None                      # verb exists but is guarded
        ev.append({"step": "cancel-probe", "result": "no cancel-family verb"})
        return None

    def _drain_window(self, grounding):
        """Fresh seam + calibrated drain inside the window (GV-4): the
        settle must then debit past zero."""
        self.drain_attempted = True
        self.state["drain_attempted"] = True
        template = next((m["marker"] for m in self.ledger.markers()
                         if m["marker"].get("create_path") and
                         m["marker"].get("amount_field")), None)
        if not template:
            return []
        create_path, field = template["create_path"], template["amount_field"]
        p = self.fresh_principal("wind")
        if p is None:
            return []
        w0 = self.wallet(p)
        if w0 is None or w0 <= 0:
            return []
        amt = max(1, w0 // 2)
        r = self.ex.request(p, "POST", create_path, body={field: amt},
                            phase=self.phase, tag="window-create")
        rb = r["resp_body"] if isinstance(r["resp_body"], dict) else {}
        shape = classify_async(r)
        if not shape:
            return []
        shape["principal"] = p.name
        shape["baseline"] = w0
        marker = self.open_from_shape(shape, grounding,
                                      "window-driver/fresh")
        if marker is None:
            return []
        ev = [{"step": "fresh-window", "amount": amt, "wallet": w0}]
        drained = self._calibrated_drain(p, w0 - amt + 1,
                                         template.get("resource"))
        ev.append({"step": "drain", "wallet_after": drained})
        settled = self._poll(shape["event_path"], p, ev)
        final = self.wallet(p)
        ev.append({"step": "final-wallet", "wallet": final,
                   "settled": settled})
        if settled and final is not None and final < 0:
            finding = self._finding(
                "FW-TOCTOU-SETTLE",
                "Async settle debits without a balance re-check: draining "
                "the wallet inside the deferred window drives the balance "
                "negative (%d)" % final,
                "critical", "I4", ["INTERRUPT"], "POST " + create_path,
                [{"balance_before": w0, "settled_amount": amt,
                  "wallet_after_drain": drained, "final_balance": final,
                  "event": shape["event_path"],
                  "resource": template.get("resource"),
                  "create_path": create_path, "amount_field": field}],
                ["any account", "sufficient balance at create time"],
                ["double-spend the prepaid balance across the async seam"])
            marker["marker"]["actions_done"].append("drain-window")
            self._resolve(marker, "confirmed", {
                "note": "violation: FW-TOCTOU-SETTLE", "wallet_trace": ev},
                finding_ids=[finding["id"]])
            # the same settled window is a second GV-5 shot (deduped later)
            f2 = self._cancel_after_settle(marker, p, amt, ev)
            if f2:
                return [finding, f2]
            return [finding]
        self._resolve(marker, "refuted" if settled else "inconclusive", {
            "note": ("drained window settled without a negative balance"
                     if settled else
                     "drained window never settled within ttl"),
            "wallet_trace": ev})
        return []

    def _calibrated_drain(self, p, need, exclude_resource):
        """Spend just above `need` with the cheapest measurable documented
        create: calibration body -> unit cost -> computed size -> verify."""
        cands = []
        for res, g in (self.surface.get("resource_actions") or {}).items():
            if not g.get("create") or res == exclude_resource:
                continue
            schema = g.get("create_schema") or {}
            ints = [f for f, s in schema.items()
                    if isinstance(s, dict) and s.get("type") == "integer"]
            if not ints:
                continue
            cands.append((res, g, ints[0]))
        cands.sort(key=lambda c: c[0])
        for res, g, field in cands:
            w = self.wallet(p)
            r1 = self._create(p, g["create"], g.get("create_schema") or {},
                              overrides={field: 1})
            w1 = self.wallet(p)
            if None in (w1, w) or w1 >= w:
                continue                     # credits or free: not a spend
            unit = w - w1
            k = int(math.ceil(float(need) / unit))
            self._create(p, g["create"], g.get("create_schema") or {},
                         overrides={field: max(1, k)})
            w2 = self.wallet(p)
            if w2 is not None and w2 < w1:
                return w2
        return self.wallet(p)

    # ------------------------------------------------------------- plumbing --
    def _resolve(self, marker, status, evidence, finding_ids=()):
        mk = marker["marker"]
        mk["state"] = "resolved"
        self.ledger.attach(marker["id"], "window-drive",
                           evidence.get("note", "driven"), 0,
                           finding_ids=finding_ids)
        self.ledger.resolve(marker["id"], status, evidence)

    def _finding(self, fid, title, sev, invar, ops, endpoint, evidence,
                 pres, grants):
        return {"id": fid, "title": title, "severity": sev,
                "invariant": invar, "operators": ops, "endpoint": endpoint,
                "evidence": evidence, "preconditions": pres,
                "grants": grants, "reproduction": [], "confidence": "high"}

    # -------------------------------------------------- verify replay (E3) --
    def verify_finding(self, fd):
        """Independent re-execution for window-driver findings: fresh
        principal, same driver code, violation re-derived from wallet
        read-backs — never from the finder's evidence (E3)."""
        fid = fd.get("id")
        contract = self._seam_contract(fd)
        if not contract:
            return ("refuted", "verification plan lacks the seam contract")
        create_path, field, amt = contract
        p = self.fresh_principal("vw")
        if p is None:
            return ("refuted", "no anon principal to bootstrap from")
        w0 = self.wallet(p)
        if w0 is None:
            return ("refuted", "no money read-back for the fresh principal")
        r = self.ex.request(p, "POST", create_path, body={field: amt},
                            phase="verify", tag="verify-window-create")
        rb = r["resp_body"] if isinstance(r["resp_body"], dict) else {}
        ev_path = event_path_of(rb)
        if r["status"] != 202 or not ev_path:
            return ("refuted", "seam did not reproduce a 202/event shape")
        if fid == "FW-TOCTOU-SETTLE":
            self._calibrated_drain(p, w0 - amt + 1, None)
            settled, final = None, None
            deadline = time.time() + 4.0
            while time.time() < deadline:
                pr = self.ex.request(p, "GET", ev_path, phase="verify",
                                     tag="event-poll")
                st = (pr["resp_body"] or {}).get("status") \
                    if isinstance(pr["resp_body"], dict) else None
                if st not in (None, "pending"):
                    settled = st
                    break
                time.sleep(0.2)
            final = self.wallet(p)
            if settled and final is not None and final < 0:
                return ("verified",
                        "fresh-principal replay: settle drove the balance "
                        "negative (%d)" % final)
            return ("refuted", "fresh replay settled without a violation")
        if fid == "FW-SETTLED-CANCEL":
            settled = self._poll(ev_path, p, [], timeout=4.0)
            w_pre = self.wallet(p)
            resource = None
            for e_ in fd.get("evidence", []):
                if isinstance(e_, dict) and e_.get("resource"):
                    resource = e_["resource"]
            oid = object_id_of(rb)
            for verb in CANCEL_VERBS:
                rc = self.ex.request(
                    p, "POST", "/api/%s/%s/%s" % (resource, oid, verb),
                    body={}, phase="verify", tag="verify-cancel")
                if rc["status"] in (404, 405):
                    continue
                w_post = self.wallet(p)
                ok = settled and None not in (w_post, w_pre) and \
                    w_post - w_pre >= amt
                return (("verified",
                         "fresh replay: cancel after settle refunded %d"
                         % (w_post - w_pre)) if ok else
                        ("refuted", "fresh replay: cancel did not refund"))
            return ("refuted", "fresh replay: no cancel verb accepted")
        return ("refuted", "no verification plan for finding id %s" % fid)

    def _seam_contract(self, fd):
        """(create_path, amount_field, amount) from the finding's own
        evidence (recorded at find time) + the marker ledger."""
        create_path = field = amt = None
        for e_ in fd.get("evidence", []):
            if isinstance(e_, dict):
                create_path = create_path or e_.get("create_path")
                field = field or e_.get("amount_field")
                amt = amt or e_.get("settled_amount") or e_.get("amount")
        if not (create_path and field and amt):
            for m in self.ledger.markers():
                mk = m["marker"]
                create_path = create_path or mk.get("create_path")
                field = field or mk.get("amount_field")
        return (create_path, field, amt) if create_path and field and amt \
            else None
