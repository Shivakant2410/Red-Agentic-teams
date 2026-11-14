"""ExperienceStore seam — per-specialist memory namespace with a bandit over
techniques and end-of-run insight curation (RESEARCH.md E1, E4, E5, M6, M7).

(# Seam: swap FileMemoryStore for the platform ExperienceStore when embedded.)

Namespace layout (memory/<name>.json):
    bandit   : {technique: {"alpha": float, "beta": float}}   posterior counts
    insights : [str]  — target-agnostic only (M7 + anti-pattern A3)
    history  : [{run, technique, outcome, weight}]            audit trail

Poisoning guard (anti-pattern A2): outcomes derived purely from target-
controlled content are recorded with weight 0.25; verified end-to-end
outcomes get 1.0; unverified wins 0.5; refuted findings are failures.
"""
import json
import os


class MemoryNamespace:
    def __init__(self, name, memory_dir, persist=True):
        # M4: persist=False gives the diskless twin used by
        # InMemoryExperienceStore (same bandit semantics, no file I/O).
        self.name = name
        self.path = (os.path.join(memory_dir, "%s.json" % name)
                     if (persist and memory_dir) else None)
        self.bandit = {}
        self.insights = []
        self.history = []
        self._load()

    # ------------------------------------------------------------- bandit ---
    def ensure(self, technique):
        self.bandit.setdefault(technique, {"alpha": 1.0, "beta": 1.0})

    def record(self, technique, outcome, weight=1.0):
        """outcome: 'success' | 'failure'.  weight: evidence strength (E4)."""
        self.ensure(technique)
        if outcome == "success":
            self.bandit[technique]["alpha"] += weight
        else:
            self.bandit[technique]["beta"] += weight
        self.history.append({"technique": technique, "outcome": outcome,
                             "weight": weight})

    def posterior_mean(self, technique):
        self.ensure(technique)
        b = self.bandit[technique]
        return b["alpha"] / (b["alpha"] + b["beta"])

    def technique_order(self, techniques):
        """Deterministic greedy-mean bandit (E1): exploit posteriors, ties by
        name. A Thompson sampler is the drop-in upgrade (flagged for GEPA-
        style offline evaluation, E2)."""
        for t in techniques:
            self.ensure(t)
        return sorted(techniques,
                      key=lambda t: (-self.posterior_mean(t), t))

    def should_run(self, technique, min_mean=0.4, min_trials=0.5):
        """Learned dead-end skip (E1): a technique with >= min_trials of
        recorded (weighted) evidence and posterior mean below min_mean is
        skipped entirely."""
        self.ensure(technique)
        b = self.bandit[technique]
        trials = b["alpha"] - 1.0 + b["beta"] - 1.0   # recorded evidence only
        if trials >= min_trials and self.posterior_mean(technique) < min_mean:
            return False
        return True

    # ------------------------------------------------------------ curation --
    def curate(self, verified_outcomes):
        """End-of-run consolidation (E5): apply outcome weights to the bandit
        and persist. `verified_outcomes`: [{technique, outcome, weight}]."""
        for o in verified_outcomes:
            self.record(o["technique"], o["outcome"], o.get("weight", 1.0))
        self._save()

    def add_insight(self, text, target_specific=False):
        """M7 + A2/A3: only target-agnostic insights may persist."""
        if target_specific:
            return False
        if text not in self.insights:
            self.insights.append(text)
            self._save()
        return True

    # -------------------------------------------------------------- io ------
    def _load(self):
        if self.path and os.path.exists(self.path):
            with open(self.path) as fh:
                doc = json.load(fh)
            self.bandit = doc.get("bandit", {})
            self.insights = doc.get("insights", [])
            self.history = doc.get("history", [])

    def _save(self):
        if self.path is None:
            return
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as fh:
            json.dump({"bandit": self.bandit, "insights": self.insights,
                       "history": self.history}, fh, indent=2)

    def snapshot(self):
        return {"name": self.name,
                "techniques": {t: round(self.posterior_mean(t), 3)
                               for t in self.bandit},
                "insights": len(self.insights),
                "trials": len(self.history)}
