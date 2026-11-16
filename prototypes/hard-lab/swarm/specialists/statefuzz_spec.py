"""LOGIC state specialist — the Phase-B statefuzz tool as a skill (M8: a
one-tool surface). Spawn-only: exploit invokes it when the FSM hypothesis
exists; it publishes every statefuzz finding as a FINDING fact whose source
provenance reads 'exploit/statefuzz_spec' (M4).
"""
import json
import os
import sys

from ..specialist import Specialist, Trigger

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


class StatefuzzSpecialist(Specialist):
    name = "statefuzz_spec"
    states = ("LOGIC",)
    max_depth = 0

    def triggers(self):
        return []          # spawn-only by design (documented contract)

    def skills(self):
        from statefuzz import build_registry
        tool = build_registry()["statefuzz_run"]
        return {"run_statefuzz": tool["run"]}

    def act(self, seed_fact, board):
        ex = self.ctx["executor"]
        remaining = self.ctx["budget"] - ex.count
        out_dir = os.path.join(self.ctx["results_dir"], "statefuzz")
        summary = self.skills()["run_statefuzz"]({
            "base_url": self.ctx["base_url"],
            "out_dir": out_dir,
            "approvals": self.ctx.get("approvals", "lab"),
            "budget": max(60, remaining),
            "stop_file": self.ctx.get("stop_file"),
        })
        doc = json.load(open(os.path.join(out_dir, "findings.json")))
        produced = []
        for fd in doc["findings"]:
            if fd.get("severity") == "info":
                continue
            produced.append(self.pub(board, "FINDING",
                {"finding": fd, "status": "candidate",
                 "technique": "h_fsm", "tool": "statefuzz"},
                confidence=0.9, tags=["h_fsm", fd["invariant"]],
                derived_from=[seed_fact["id"]]))
        self.private.setdefault("outcomes", {})["run_statefuzz"] = \
            "success" if produced else "failure"
        self.private.setdefault("tech_facts", {})["run_statefuzz"] = \
            [f["id"] for f in produced]
        return produced
