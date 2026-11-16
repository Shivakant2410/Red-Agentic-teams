"""PREEX state specialist (M5) — the offensive core's evidence layer.

Runs the pre-exploitation ladder (techniques_preex) when the surface map
lands, and publishes what it SAW: an authz matrix with denials recorded at
the same fidelity as grants, an object map per principal, hidden-parameter
differentials. Where the evidence confirms a precondition, it raises the
matching hypothesis WITH that evidence attached (Sarraute's POMDP mixing:
information-gathering actions feed the exploit decision — the exploit
specialist stops rediscovering what recon already knew).

Publishes OBSERVATION facts only (plus evidence-backed HYPOTHESSES); never
findings — the verify pipeline owns confirmation. Arms record outcomes to
its memory namespace so the bandit learns which pre-ex arms pay per shape
(E1, unchanged machinery).
"""
from ..specialist import Specialist, Trigger
from .. import techniques as T
from .. import techniques_preex as PX


class PreExSpecialist(Specialist):
    name = "preex"
    states = ("PREEX",)

    def triggers(self):
        # fires after the surface mapper (priority 2.0/1.9) has spoken and
        # before exploit's HYPOTHESIS consumers (1.5)
        return [Trigger("SURFACE", lambda f, b: True, 1.7)]

    def skills(self):
        return {"probe": lambda m, meth, p, body=None:
                self.ctx["executor"].request(m, meth, p, body=body,
                                             phase="preex")}

    # ------------------------------------------------------------------ act --
    def act(self, fact, board):
        ex = self.ctx["executor"]
        surface = fact["payload"]
        # ladder gate (Sarraute: an action must earn its requests): only on
        # a real surface, with enough budget left for the exploit layer
        if not surface.get("resource_actions") or ex.count < 0 or \
                (self.ctx["budget"] - ex.count) < 60:
            self.memory.record("preex_ladder", "failure", 0.5)
            return []
        # one ladder per run (the surface may be revised several times)
        if "ladder_done" in self.private:
            return []
        self.private["ladder_done"] = True

        env = T.Env(ex, self.ctx["anon"], surface, self.ctx["budget"],
                    artifacts=self.ctx.get("artifacts"),
                    phase="preex",
                    notes=self.private.setdefault("notes", {}))
        # target-derived parameter pool (M5): recon's harvested vocabulary +
        # every field name observed on the wire so far — the target's own
        # response bodies outrank generic class hints (Arjun-with-provenance)
        pool = set(env.notes.get("param_pool") or [])
        try:
            for f2 in board.query(kind="OBSERVATION"):
                if "param-pool" in (f2.get("tags") or []):
                    pool.update(f2["payload"].get("param_pool") or [])
        except Exception:
            pass
        pool.update(PX.traffic_keys(ex.traffic_path))
        env.notes["param_pool"] = sorted(pool)[:80]
        outcomes, payloads = PX.run(env, budget_cap=70)
        for tech, oc in outcomes.items():
            self.memory.record(tech, oc, 1.0)
        self.memory.record("preex_ladder",
                           "success" if payloads else "failure", 0.75)

        produced = []
        for name, payload in payloads.items():
            produced.append(self.pub(board, "OBSERVATION", payload,
                                     tags=["preex", name],
                                     derived_from=[fact["id"]]))
        # evidence-raised hypotheses: only where the matrix/probe confirmed
        # a precondition. Priors: keyword rules stay the floor (hypothesis.py),
        # observed evidence raises them — never lowers, never concludes.
        tested = self.private.setdefault("raised", set())
        for payload in payloads.values():
            for tag, prior, evidence, summary in \
                    PX.hypotheses_from(payload):
                if tag in tested:
                    continue
                tested.add(tag)
                produced.append(self.pub(board, "HYPOTHESIS", {
                    "tag": tag, "status": "open", "prior": prior,
                    "evidence": evidence, "origin": "preex",
                    "summary": summary},
                    tags=[tag, "preex-raised"],
                    derived_from=[f["id"] for f in produced] or
                                 [fact["id"]]))
        return produced
