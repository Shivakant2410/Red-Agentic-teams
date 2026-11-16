# -*- coding: utf-8 -*-
"""statefuzz — LLM-inferred state machines + metamorphic invariant oracles for
business-logic fuzzing. Prototype for the Red-Agentic-teams registry.

Theory map (dossier Ch.8 -> code):
    M = (S, s0, Sigma, delta, F)     -> appmodel.AppStateModel
    alpha (abstraction function)     -> AppStateModel.abstraction()
    five invariant classes I1..I5    -> invariants.py
    eight transition mutant operators-> mutants.py
    four oracle kinds                -> oracle.py
    findings-as-capabilities, chains -> chains.py
    main loop (dossier 9.3)          -> runner.statefuzz_run(ctx, budget)
"""
__version__ = "0.1.0"

from .appmodel import AppStateModel, Transition, RequestPlan, Response, ObservedState
from .runner import statefuzz_run, RunReport
from .tools import build_statefuzz_tools

__all__ = [
    "AppStateModel", "Transition", "RequestPlan", "Response", "ObservedState",
    "statefuzz_run", "RunReport", "build_statefuzz_tools", "__version__",
]
