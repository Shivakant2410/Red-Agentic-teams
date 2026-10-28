"""Benchmark harness: score the agent against known-vulnerable targets.

'Better than the market' is only real as a number. This package stands up deliberately
vulnerable apps you own (Juice Shop, DVWA, WebGoat), runs the agent, and scores its
confirmed findings against a ground-truth vulnerability list: true/false positives,
precision/recall, and coverage. Wire it into CI to catch harness regressions.
"""
