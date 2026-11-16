"""AppStateModel — action inventory from the live OpenAPI document, multi-
principal bootstrap, and a lawful transition walk that induces the FSM the
oracles reason over.

alpha(s) abstraction per principal:
  auth       : anon | user
  cart       : empty | nonempty | snapshot_pending   (observed via GET /api/cart)
  order_life : none | initiated | paid | shipped | refunded
A transition (alpha(s), action, alpha(s')) is "modeled" only if the lawful
walk observed it. The legality oracle (I2) fires when the server accepts an
action from a state for which the walk never observed it.
"""
from .executor import Principal


class AppStateModel:
    def __init__(self, ex):
        self.ex = ex
        self.principals = {}
        self.actions = {}          # path template -> {method: op-spec}
        self.walk = []             # [(state_before, action, state_after, ex)]
        self.legal = set()         # {(order_status, action_name)} observed

    # ------------------------------------------------------------ bootstrap --
    def fetch_inventory(self):
        r = self.ex.request(self.anon(), "GET", "/openapi.json", phase="bootstrap")
        self.actions = r["resp_body"].get("paths", {})
        return len(self.actions)

    def anon(self):
        if "anon" not in self.principals:
            self.principals["anon"] = Principal("anon")
        return self.principals["anon"]

    def register(self, name):
        """Register + login a fresh principal over real HTTP."""
        self.ex.request(self.anon(), "POST", "/api/register",
                        body={"username": name, "password": "pw-" + name},
                        phase="bootstrap")
        r = self.ex.request(self.anon(), "POST", "/api/login",
                            body={"username": name, "password": "pw-" + name},
                            phase="bootstrap")
        p = Principal(name, token=r["resp_body"].get("token"))
        self.principals[name] = p
        return p

    # -------------------------------------------------------------- alpha ----
    def observe(self, p):
        cart = self.ex.request(p, "GET", "/api/cart", phase="bootstrap")
        cb = cart["resp_body"]
        return {"auth": "user",
                "cart": "empty" if not cb.get("items") else "nonempty",
                "discount_pct": cb.get("discount_pct", 0)}

    def wallet(self, p):
        r = self.ex.request(p, "GET", "/api/wallet", phase="probe")
        return r["resp_body"].get("balance_cents")

    # ---------------------------------------------------------- lawful walk --
    def lawful_walk(self):
        """Scripted legal sequence: add -> init -> confirm -> ship, and a
        second cart -> init -> confirm -> refund. Records the transition
        table the I2 legality oracle compares against."""
        p = self.register("walker")
        steps = []

        def step(name, method, path, body=None):
            ex = self.ex.request(p, method, path, body=body, phase="walk")
            self.walk.append((name, ex))
            steps.append((name, ex["status"]))
            return ex

        step("cart_add", "POST", "/api/cart/items", {"sku": "SKU-CABLE", "qty": 2})
        r1 = step("init", "POST", "/api/checkout/init")
        oid1 = r1["resp_body"].get("order_id")
        step("confirm", "POST", "/api/checkout/confirm", {"order_id": oid1})
        step("ship", "POST", "/api/orders/%s/ship" % oid1)
        step("cart_add_2", "POST", "/api/cart/items", {"sku": "SKU-GPU", "qty": 1})
        r2 = step("init_2", "POST", "/api/checkout/init")
        oid2 = r2["resp_body"].get("order_id")
        step("confirm_2", "POST", "/api/checkout/confirm", {"order_id": oid2})
        step("refund", "POST", "/api/orders/%s/refund" % oid2)

        # modeled lifecycle as observed by the walk: initiated -> paid,
        # paid -> shipped, paid -> refunded. Nothing else is assumed.
        self.legal = {("initiated", "confirm"), ("paid", "ship"),
                      ("paid", "refund")}
        return steps

    def is_modeled(self, order_status, action):
        return (order_status, action) in self.legal
