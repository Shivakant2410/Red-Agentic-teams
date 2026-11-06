"""HYPOTHESES state specialist — the max-entropy LLM seam (seam 1, E6).

Deterministic rule engine generates invariant-violation hypotheses from the
surface graph. When an LLM backend is plugged into the seam, its candidates
are MERGED in as hypotheses with their own priors — never as conclusions:
every hypothesis must be tested by exploit before it can become a finding
(grounded-only reasoning, Huang et al.).
"""
from ..specialist import Specialist, Trigger

RULES = [
    ("h_race", "Single-use redemption may lose check-then-act races",
     0.50, "last-byte-synchronised race, 8 workers"),
    ("h_async", "Async refund leg may double-credit within the callback "
                "window", 0.55, "async refund + sync refund, poll callback"),
    ("h_idor", "Parameterised object endpoints may lack ownership checks",
     0.60, "cross-user read of a fresh order"),
    ("h_refund", "Refund transitions may be replayable and mis-credited",
     0.60, "replay refund x2 as a second principal"),
    ("h_coupon", "Multi-use coupon application may stack without cap",
     0.50, "replay coupon/apply x12"),
    ("h_fsm", "Order lifecycle is a two-step state machine; transition "
              "guards may be missing", 0.70, "spawn statefuzz specialist"),
]

# ------------------------------------------------------- generic rules -----
# v0.2: surface-driven rules that fire on ANY target whose openapi resource
# graph matches the shape. Order == expected cost (cheap probes first) so a
# tight budget starves the expensive ones last. Gated on graph shapes, never
# on target-specific names.
GENERIC_RULES = [
    ("h_hidden_verbs", "Parameterised money resources may expose undocumented "
     "ops verbs", 0.40, "verb wordlist probe on param paths"),
    ("h_state_guard", "Cancel-terminated resources may leave sibling write "
     "verbs open and the dedupe keyed to the body", 0.55,
     "create -> cancel -> replay/mutate -> sibling write"),
    ("h_mass_assign", "Undocumented body fields may override pricing or "
     "entitlements", 0.50, "differential create with injected candidates"),
    ("h_cross_tenant", "Global read-backs may leak other tenants' ids; leaked "
     "ids may pay the caller", 0.50,
     "cross-principal readback scan + deputy write"),
    ("h_async_toctou", "Async settles may debit without re-checking the "
     "balance", 0.55, "create async -> drain balance -> await settle"),
    ("h_terminal_credit", "Cancel of a settled async artifact may refund "
     "after delivery", 0.50, "create async -> settle -> cancel"),
    ("h_arith_cycle", "Value-neutral cycles of a priced transition may "
     "accumulate rounding drift", 0.45, "cycle 12x, net wallet delta"),
    ("h_quota_race", "Quota-limited claims may lose the check-then-act race "
     "to distinct principals", 0.50, "multi-principal last-byte race"),
    ("h_async_seam", "A money surface with no documented async seam may "
     "hide one (deferred-effect lifecycle with unguarded settle/cancel)",
     0.45, "noun-probe resource creates; learn the field from the error "
           "contract; open one seam; window driver takes it from there"),
]


def _generic_gate(tag, surface):
    graph = surface.get("resource_actions") or {}
    actions = [a for g in graph.values() for a in g.get("actions", [])]
    if tag == "h_hidden_verbs":
        return any(g.get("param") and g.get("create") for g in
                   graph.values())
    if tag == "h_state_guard":
        return any(a.get("verb") in
                   ("cancel", "revoke", "close", "terminate")
                   for a in actions)
    if tag == "h_mass_assign":
        return any(g.get("create") for g in graph.values())
    if tag == "h_cross_tenant":
        return any(g.get("param") and g.get("create")
                   for g in graph.values()) and \
            bool(surface.get("readback"))
    if tag == "h_async_toctou":
        return any(a.get("verb") in ("transfer", "send", "move", "gift")
                   for a in actions) and \
            any(g.get("create") for g in graph.values())
    if tag == "h_terminal_credit":
        return any(a.get("verb") in
                   ("cancel", "revoke", "close", "terminate")
                   for a in actions) and \
            any(g.get("create") for g in graph.values())
    if tag == "h_arith_cycle":
        # hard-lab upgrade U3: schema_unknown actions are probeable via the
        # 422 error contract, so an empty schema no longer gates the rule out.
        return any(a.get("method") == "POST" and
                   (a.get("schema_unknown") or
                    (any(isinstance(s, dict) and s.get("type") == "integer"
                         for s in (a.get("schema") or {}).values())))
                   for a in actions) and \
            any(g.get("create") for g in graph.values())
    if tag == "h_quota_race":
        return any(a.get("verb") in ("claim", "redeem", "consume", "activate")
                   for a in actions)
    if tag == "h_async_seam":
        # money target (a discovered read-back) with NO documented async
        # seam — the stale-doc class where deferred windows hide (G1)
        documented = [str(p).lower() for p in (surface.get("endpoints") or [])]
        async_doc = any(w in p for p in documented
                        for w in ("async", "callback", "/events"))
        return bool(surface.get("readback")) and not async_doc and \
            any(g.get("create") for g in graph.values())
    return False


class HypothesisEngine(Specialist):
    name = "hypothesis"
    states = ("HYPOTHESES",)

    def triggers(self):
        return [Trigger("SURFACE", None, 2.0)]

    def skills(self):
        return {"generate": self._rules}

    @staticmethod
    def _rules(surface):
        out = []
        if surface.get("redeem"):
            out.append(RULES[0])
        if surface.get("async"):
            out.append(RULES[1])
        if surface.get("param_objects"):
            out.append(RULES[2])
        if surface.get("refund"):
            out.append(RULES[3])
        if surface.get("coupon"):
            out.append(RULES[4])
        if surface.get("stateful_flows"):
            out.append(RULES[5])
        return out

    def act(self, fact, board):
        surface = fact["payload"]
        existing = {h["payload"]["tag"] for h in board.query(kind="HYPOTHESIS")}

        candidates = [(t, title, prior, plan, "rules")
                      for t, title, prior, plan in self._rules(surface)]

        # ---- v0.2 generic rules: surface-graph gated, any target ----------
        for tag, title, prior, plan in GENERIC_RULES:
            if _generic_gate(tag, surface):
                candidates.append((tag, title, prior, plan, "generic-rules"))

        # ---- LLM seam 1: merged candidates carry their own priors --------
        llm = self.ctx["llm"]
        llm_out = llm.generate_hypotheses(fact)
        if llm_out:
            for h in llm_out[:4]:
                tag = "h_llm_" + str(h.get("kind_tag", "x"))[:24]
                candidates.append((tag, str(h.get("title", ""))[:140],
                                   float(h.get("prior", 0.4)),
                                   str(h.get("test_plan", ""))[:160],
                                   "llm-seam"))

        produced = []
        for tag, title, prior, plan, origin in candidates:
            if tag in existing:
                continue
            produced.append(self.pub(board, "HYPOTHESIS",
                {"tag": tag, "title": title, "prior": prior,
                 "test_plan": plan, "origin": origin, "status": "open"},
                confidence=prior, tags=[tag], derived_from=[fact["id"]]))
        self.private.setdefault("outcomes", {})["generate"] = \
            "success" if produced else "failure"
        self.private.setdefault("tech_facts", {})["generate"] = \
            [f["id"] for f in produced]
        return produced
