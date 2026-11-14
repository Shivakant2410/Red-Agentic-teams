"""statefuzz — LLM-optional state-machine business-logic fuzzer (Phase B prototype).

Implements the S9 spec of the Red-Agentic-teams dossier:
  model.py       AppStateModel (action inventory + lawful walk + abstraction alpha)
  invariants.py  5 invariant classes as executable oracles (I1..I5)
  mutants.py     8 transition mutant operators (pure transforms, unit-testable)
  executor.py    real-HTTP executor: budget, STOP file, traffic.jsonl, last-byte race
  oracle.py      immediate metamorphic oracles + deferred HypothesisLedger
  chains.py      findings-as-capabilities reachability (confused-deputy chaining)
  registry_tool.py  build_registry() -> {"statefuzz_run": {schema(), run(ctx)}}
"""
__version__ = "0.1.0"

from .registry_tool import build_registry  # noqa: F401
