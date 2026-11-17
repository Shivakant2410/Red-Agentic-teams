"""The campaign brain — cross-family target intelligence + orchestration.

The family lanes (pi, sid, sc) each own a good attacker loop and a good
mechanical oracle, but until this package they shared NOTHING: each brain
kept its bandit state inside the run, learned the same target from zero
every time, and died at process exit. This package is the missing organ:

  profile.py       — TargetProfile: one persisted per-target ledger every
                     lane reads and writes (cipher competence, family
                     tallies, pinned notes). Facts flow SIDEWAYS.
  orchestrator.py  — FamilyOrchestrator: sequences family lanes under ONE
                     budget, prunes dead branches (TAP), presses proven
                     weaknesses, reports coverage.

Divergences from the cited literature are stated in each module.
"""

from .orchestrator import FamilyOrchestrator
from .profile import REWARD, TargetProfile, fingerprint_target

__all__ = ["REWARD", "TargetProfile", "FamilyOrchestrator",
           "fingerprint_target"]
