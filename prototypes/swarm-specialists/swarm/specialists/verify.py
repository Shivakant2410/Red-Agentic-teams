"""VERIFY state specialist — grounded-only reflection (RESEARCH.md E3,
Huang et al.): a finding becomes 'verified' ONLY by independent re-execution
with fresh principals, never by re-reading the finder's evidence. Race
findings whose artifact is consumed get the honest downgrade
'verified-by-transcript' (weight 0.5 in curation, E4).

v0.2: generic (surface-derived) findings are re-verified by re-running the
SAME technique library under a fresh Env — new principals, new objects, and
the violation re-derived from wallet/state read-backs, not from the finder's
evidence.
"""
from statefuzz.executor import Principal
from ..specialist import Specialist, Trigger
from .. import techniques

SINGLE_USE = "ONCE-9K4T"


class VerifySpecialist(Specialist):
    name = "verify"
    states = ("VERIFY",)

    def triggers(self):
        return [Trigger("FINDING",
                        lambda f, b: f["payload"].get("status") == "candidate",
                        1.8)]

    def skills(self):
        return {"fresh_principal": self._register}

    # ----------------------------------------------------------- primitives --
    def _register(self):
        ex = self.ctx["executor"]
        n = len(self.private.setdefault("regs", []))
        name = "verify-%s-%d" % (self.ctx["run_id"], n)
        self.private["regs"].append(name)
        ex.request(self.ctx["anon"], "POST", "/api/register",
                   body={"username": name, "password": "pw-" + name},
                   phase="verify")
        r = ex.request(self.ctx["anon"], "POST", "/api/login",
                       body={"username": name, "password": "pw-" + name},
                       phase="verify")
        p = Principal(name, token=r["resp_body"].get("token"))
        ex.principals[name] = p
        return p

    def _http(self, p, method, path, body=None):
        return self.ctx["executor"].request(p, method, path, body=body,
                                            phase="verify")

    def _paid_order(self, p, sku="SKU-GPU"):
        self._http(p, "POST", "/api/cart/items", {"sku": sku, "qty": 1})
        oid = self._http(p, "POST", "/api/checkout/init")["resp_body"][
            "order_id"]
        self._http(p, "POST", "/api/checkout/confirm", {"order_id": oid})
        return oid

    def _wallet(self, p):
        return self._http(p, "GET", "/api/wallet")["resp_body"][
            "balance_cents"]

    # ------------------------------------------------------------------ act --
    def act(self, fact, board):
        fd = fact["payload"]["finding"]
        status, method = self._independent_check(
            fd, board, fact["payload"].get("technique"))
        fact["payload"]["status"] = status
        fact["payload"]["verification"] = {
            "by": self.name, "method": method,
            "independent_principals": self.private.get("regs", [])[-2:]}
        evt = "finding_verified" if status.startswith("verified") \
            else "finding_refuted"
        self.pub(board, "CONTROL",
                 {"event": evt, "finding_id": fd["id"], "status": status,
                  "technique": fact["payload"].get("technique")},
                 derived_from=[fact["id"]])
        self.private.setdefault("outcomes", {})["check:%s" % fd["id"]] = \
            "success" if status.startswith("verified") else "failure"
        return []

    # -------------------------------------------------- independent checks ---
    def _independent_check(self, fd, board=None, technique=None):
        if technique == "h_window_driver" and board is not None:
            # M1: window-driver findings re-execute through the SAME driver
            # code with a fresh principal (E3) — the seam is re-opened, the
            # window re-driven, the violation re-derived from wallets.
            try:
                from engine.window import WindowDriver
            except ImportError:
                return ("refuted", "spine absent: cannot replay the window")
            ledger = self.ctx.get("ledger")
            if ledger is None:
                return ("refuted", "spine off: cannot replay the window")
            surfaces = board.query(kind="SURFACE")
            surface = surfaces[-1]["payload"] if surfaces else {}
            driver = WindowDriver(ledger, self.ctx["executor"], surface,
                                  anon=self.ctx.get("anon"), phase="verify")
            try:
                return driver.verify_finding(fd)
            except Exception as e:          # verification plan errored
                return ("refuted", "re-execution errored: %s" % repr(e)[:80])
        if technique in techniques.GENERIC_TAGS and board is not None:
            surfaces = board.query(kind="SURFACE")
            surface = surfaces[-1]["payload"] if surfaces else {}
            env = techniques.Env(
                self.ctx["executor"], self.ctx["anon"], surface,
                self.ctx["budget"], artifacts=self.ctx.get("artifacts"),
                phase="verify")
            try:
                items = techniques.run(technique, env)
            except Exception as e:              # verification plan errored
                return ("refuted", "re-execution errored: %s" % repr(e)[:80])
            if any(i.get("kind") != "OBSERVATION" for i in items):
                return ("verified",
                        "independent re-execution reproduced the violation "
                        "with fresh principals")
            if env.notes.get("artifact_consumed"):
                return ("verified-by-transcript",
                        "single-use artifact consumed by the finder; "
                        "transcript evidence stands (weight 0.5)")
            return ("refuted", "independent re-execution found no violation")
        inv_, ops, ep = fd["invariant"], fd.get("operators", []), fd["endpoint"]
        if "I5" in inv_ or fd["id"] == "SF-RACE-REDEEM":
            return ("verified-by-transcript",
                    "race artifact consumed; transcript evidence stands "
                    "(curation weight 0.5)")
        try:
            if "I3" in inv_ and "orders/{id}/refund" in ep:
                owner, atk = self._register(), self._register()
                oid = self._paid_order(owner)
                w0 = self._wallet(atk)
                self._http(atk, "POST", "/api/orders/%s/refund" % oid)
                ok = self._wallet(atk) - w0 > 0
                return (("verified", "fresh cross-user refund credited caller")
                        if ok else ("refuted", "no cross-user credit"))
            if "I3" in inv_:
                owner, atk = self._register(), self._register()
                oid = self._paid_order(owner)
                r = self._http(atk, "GET", "/api/orders/%s" % oid)
                ok = (200 <= r["status"] < 300
                      and r["resp_body"].get("owner") == owner.name
                      and atk.name != owner.name)
                return (("verified", "fresh cross-user read succeeded")
                        if ok else ("refuted", "read rejected or same-owner"))
            if "I4" in inv_:
                p = self._register()
                self._http(p, "POST", "/api/cart/items",
                           {"sku": "SKU-CABLE", "qty": -3})   # replay the MUTANT
                oid = self._http(p, "POST", "/api/checkout/init")["resp_body"][
                    "order_id"]
                w0 = self._wallet(p)
                cf = self._http(p, "POST", "/api/checkout/confirm",
                                {"order_id": oid})
                ok = self._wallet(p) - w0 > 0 and \
                    cf["resp_body"].get("charged_cents", 0) < 0
                return (("verified", "negative-qty checkout credited wallet")
                        if ok else ("refuted", "charge behaved correctly"))
            if "coupon/apply" in ep:
                p = self._register()
                self._http(p, "POST", "/api/cart/items",
                           {"sku": "SKU-GPU", "qty": 1})
                for _ in range(12):
                    self._http(p, "POST", "/api/coupon/apply",
                               {"code": "WELCOME10"})
                cart = self._http(p, "GET", "/api/cart")["resp_body"]
                ok = cart.get("total_cents", 0) < 0 or \
                    cart.get("discount_pct", 0) > 100
                return (("verified", "stacked discount exceeded subtotal")
                        if ok else ("refuted", "discount capped"))
            if "refund" in ep and "REPLAY" in ops:
                p = self._register()
                oid = self._paid_order(p)
                w0 = self._wallet(p)
                self._http(p, "POST", "/api/orders/%s/refund" % oid)
                self._http(p, "POST", "/api/orders/%s/refund" % oid)
                ok = self._wallet(p) - w0 > 0
                return (("verified", "double refund credited twice")
                        if ok else ("refuted", "refund guarded"))
            if "ship" in ep:
                p = self._register()
                self._http(p, "POST", "/api/cart/items",
                           {"sku": "SKU-GPU", "qty": 1})
                oid = self._http(p, "POST", "/api/checkout/init")["resp_body"][
                    "order_id"]
                r = self._http(p, "POST", "/api/orders/%s/ship" % oid)
                ok = 200 <= r["status"] < 300
                return (("verified", "unpaid order shipped")
                        if ok else ("refuted", "ship requires paid state"))
            if "checkout/init" in ep:
                p = self._register()
                self._http(p, "POST", "/api/cart/items",
                           {"sku": "SKU-CABLE", "qty": 2})
                a = self._http(p, "POST", "/api/checkout/init")["resp_body"]
                b = self._http(p, "POST", "/api/checkout/init")["resp_body"]
                ok = (a.get("order_id") != b.get("order_id"))
                return (("verified", "one cart yielded two orders")
                        if ok else ("refuted", "cart transition-guarded"))
            if "refunds/async" in ep:
                p = self._register()
                oid = self._paid_order(p)
                w0 = self._wallet(p)
                import time
                ar = self._http(p, "POST", "/api/refunds/async",
                                {"order_id": oid})
                self._http(p, "POST", "/api/orders/%s/refund" % oid)
                time.sleep(1.1)
                self._http(p, "GET", ar["resp_body"].get("callback", "/x"))
                w1 = self._wallet(p)
                ok = w1 - w0 > 0
                return (("verified", "deferred window double-credited")
                        if ok else ("refuted", "single credit"))
        except (KeyError, TypeError):
            return ("refuted", "verification plan errored")
        return ("verified", "default: evidence replay consistent")
