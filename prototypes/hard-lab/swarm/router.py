"""Router — the progress-ledger loop (Magentic-One, M3) over a blackboard of
knowledge sources (Hearsay-II, M1).

Per round: consume new facts, collect (trigger, specialist) matches from
specialists whose CONTRACT holds, dispatch by priority (LLM seam only for
tie-breaks, E6), record the dispatch trace. Two consecutive empty rounds =>
escalation fact; three => stop (stall detection by counter). Global HTTP
budget is checked every round.
"""
import time

from .blackboard import Fact
from .specialist import ContractViolation


class Router:
    def __init__(self, board, specialists, ctx):
        self.board = board
        self.specialists = specialists
        self.ctx = ctx
        self.trace = []
        self.rounds = 0
        self.stall_rounds = 0
        self.spawn_events = []

    # ------------------------------------------------------------ contract --
    def _contract_ok(self, specialist):
        """M2: machine-checkable spec. Max skill surface 8 (M8); per-specialist
        dispatch cap from ctx; triggers must be typed."""
        if len(specialist.skills()) > 8:
            return "skill surface too wide (%d)" % len(specialist.skills())
        cap = self.ctx.get("per_specialist_dispatch_cap", 12)
        if specialist.dispatches >= cap:
            return "dispatch cap reached (%d)" % cap
        for t in specialist.triggers():
            if t.kind not in ("OBSERVATION", "SURFACE", "HYPOTHESIS",
                              "FINDING", "ESCALATION", "CONTROL"):
                return "bad trigger kind %r" % t.kind
        return None

    # ------------------------------------------------------------- helpers --
    def _out_of_budget(self):
        ex = self.ctx.get("executor")
        budget = self.ctx.get("budget", 400)
        return ex is not None and ex.count >= budget

    def log(self, **entry):
        entry["ts"] = time.time()
        entry["round"] = self.rounds
        self.trace.append(entry)

    # ---------------------------------------------------------------- run ----
    def dispatch(self, max_rounds=40):
        seq = 0
        pending = []            # candidate dispatches not yet executed
        consumed = set()        # (fact_id, specialist.name) pairs already run
        while self.rounds < max_rounds:
            if self._out_of_budget():
                self.log(event="budget-exhausted",
                         requests=self.ctx["executor"].count)
                break
            new = self.board.since(seq)
            seq = self.board.length
            for f in new:
                for s in self.specialists:
                    for t in s.triggers():
                        if t.matches(f, self.board):
                            pending.append({"specialist": s, "trigger": t,
                                            "fact": f, "priority": t.priority})
            pending = [c for c in pending
                       if (c["fact"]["id"], c["specialist"].name)
                       not in consumed]
            if not pending:
                self.stall_rounds += 1
                if self.stall_rounds >= 3:
                    self.log(event="stop-stalled")
                    break
                if self.stall_rounds == 2:
                    self.board.publish(Fact.make(
                        "CONTROL", "router",
                        {"event": "stall-escalate", "round": self.rounds}))
                    self.log(event="stall-escalate")
                self.rounds += 1
                continue

            self.stall_rounds = 0
            pending.sort(key=lambda c: -c["priority"])
            top = [c for c in pending
                   if c["priority"] == pending[0]["priority"]]
            chosen = self.ctx["llm"].tie_break(top)     # seam 2 (E6)
            s, t, f = chosen["specialist"], chosen["trigger"], chosen["fact"]
            consumed.add((f["id"], s.name))

            violation = self._contract_ok(s)
            if violation:
                self.log(event="contract-refused", specialist=s.name,
                         reason=violation, fact=f["id"])
                self.rounds += 1
                continue

            before = self.board.length
            produced = s.act(f, self.board) or []
            s.dispatches += 1
            spawned = [p["payload"].get("spawned") for p in produced
                       if p["payload"].get("spawned")]
            self.spawn_events += spawned
            self.log(event="dispatch", specialist=s.name,
                     provenance=getattr(s, "provenance", s.name),
                     fact=f["id"], trigger_kind=t.kind,
                     priority=t.priority, produced=[p["id"] for p in produced],
                     new_facts=self.board.length - before,
                     pending=len(pending))
            self.rounds += 1

        self.log(event="done", rounds=self.rounds,
                 ledger=self.board.ledger())
        return self.trace
