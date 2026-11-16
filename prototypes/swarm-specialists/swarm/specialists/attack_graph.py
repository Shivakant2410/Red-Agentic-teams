"""ATTACKGRAPH specialist — M3: the evidence graph steering the run.

The graph is INDUCED (engine/attackgraph.build) from the run's own facts —
surface truth, credited verb facts, async seams, findings with verification
states, ambient wallet events — never from a template. It is rebuilt and
saved as attack_surface.json each time it fires, and its next_actions()
ranking is converted into HYPOTHESIS facts the existing router already
dispatches: the graph guides exploit agents through the standard loop,
no new machinery. Guidance is bounded (<= 2 graph-guided hypotheses per
run, prior 0.45, origin "attack-graph") and deterministic (no LLM).

Fires on: ambient-credit ESCALATION (money moved unexplained — the band-D
bridge) and CONTROL stall-escalate (the run is stuck — cheapest untested
edges to the money goal are exactly what a stalled run needs).
"""
from ..specialist import Specialist, Trigger


class AttackGraphSpecialist(Specialist):
    name = "attack_graph"
    states = ("CONTROL",)
    MAX_GUIDED = 2

    def triggers(self):
        # ambient-credit outranks the hypothesis engine's SURFACE trigger
        # (2.0): money moved unexplained is the run's most urgent signal,
        # and the graph must guide BEFORE the deterministic rules fire —
        # the rules remain the fallback when the graph has no suggestion.
        return [Trigger("ESCALATION",
                        lambda f, b: f["payload"].get("event")
                        == "ambient-credit", 2.5),
                Trigger("CONTROL",
                        lambda f, b: f["payload"].get("event")
                        == "stall-escalate", 1.2)]

    def skills(self):
        return {}          # the graph never issues a request (pure board art)

    def act(self, fact, board):
        try:
            from engine import attackgraph as ag
        except ImportError:
            return []                      # spine absent: v1 path unchanged
        ambient = self.ctx.get("ambient_events") or []
        tested = {h["payload"]["tag"] for h in board.query(kind="HYPOTHESIS")}
        doc = ag.build(board.facts, ambient_events=ambient,
                       tested_tags=tested)
        path = ag.save(doc, self.ctx["results_dir"])
        produced = [self.pub(board, "OBSERVATION",
            {"attack_graph": {"money_paths": doc["money_paths"],
                              "next_actions": doc["next_actions"],
                              "surface_nodes":
                                  len(doc["surface_map"]["nodes"]),
                              "surface_edges":
                                  len(doc["surface_map"]["edges"])},
             "artifact": path,
             "evidence": "attack graph rebuilt from board facts + ambient "
                         "wallet events (%d)" % len(ambient)},
            tags=["attack-graph"], derived_from=[fact["id"]])]

        # guidance: cheapest untested money edges -> hypotheses (bounded)
        tested = {h["payload"]["tag"] for h in board.query(kind="HYPOTHESIS")}
        guided = self.private.get("guided", 0)
        for na in doc["next_actions"]:
            if guided >= self.MAX_GUIDED:
                break
            tag = na.get("technique")
            if not tag or tag in tested:
                continue
            tested.add(tag)
            guided += 1
            produced.append(self.pub(board, "HYPOTHESIS",
                {"tag": tag,
                 "title": "attack-graph: untested money edge %s %s"
                          % (na.get("resource"), na.get("verb")),
                 "prior": 0.45,
                 "test_plan": "graph-guided: cheapest untested edge to the "
                              "wallet goal (~%s requests)"
                              % na.get("requests"),
                 "origin": "attack-graph", "status": "open"},
                confidence=0.45, tags=[tag, "attack-graph"],
                derived_from=[fact["id"]]))
        self.private["guided"] = guided
        return produced
