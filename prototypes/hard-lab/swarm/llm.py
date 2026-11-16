"""LLM seam — max-entropy placement (RESEARCH.md E6 + Phase-A S8 principle).

The LLM fires ONLY at induction / high-uncertainty points:
  seam 1  hypothesis generation from unexplained observations (hypoth- specialist)
  seam 2  router tie-break between equal-priority dispatches

Default backend is None -> deterministic heuristics run (this prototype's
demo mode). Plug a real backend by passing `backend=callable(prompt)->str`
(# Seam: wire to the platform's LLM when embedded). Every LLM output enters
the blackboard as a HYPOTHESIS with a prior — never as a conclusion (E6:
no self-confidence routing; exploit must test before promote).
"""
import json


class LLMSeam:
    SEAMS = ("hypothesis_generation", "router_tie_break")

    def __init__(self, backend=None):
        self.backend = backend
        self.calls = []

    def available(self):
        return self.backend is not None

    def generate_hypotheses(self, surface_fact):
        """Seam 1. Returns list of {kind_tag, title, prior, test_plan}."""
        if self.backend is None:
            return None            # caller falls back to deterministic rules
        prompt = ("You are a business-logic pentest hypothesis engine. "
                  "Given this attack-surface fact as JSON, propose up to 4 "
                  "hypotheses of invariant violations. Reply with a JSON "
                  "list of {kind_tag, title, prior, test_plan}.\n"
                  + json.dumps(surface_fact["payload"])[:4000])
        self.calls.append({"seam": "hypothesis_generation", "ts": surface_fact["ts"]})
        try:
            return json.loads(self.backend(prompt))
        except (ValueError, TypeError):
            return None            # malformed LLM output -> deterministic path

    def tie_break(self, choices):
        """Seam 2. choices: list of equal-priority (specialist, trigger).
        Deterministic fallback: first by registration order."""
        if self.backend is None or len(choices) < 2:
            return choices[0] if choices else None
        self.calls.append({"seam": "router_tie_break", "n": len(choices)})
        return choices[0]
