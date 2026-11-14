"""Specialist roster — one specialist per engagement state."""
from .recon import ReconSpecialist
from .surface_mapper import SurfaceMapper
from .hypothesis import HypothesisEngine
from .exploit import ExploitSpecialist
from .verify import VerifySpecialist
from .access import AccessSpecialist
from .statefuzz_spec import StatefuzzSpecialist
from .window_driver import WindowDriverSpecialist
from .attack_graph import AttackGraphSpecialist
from .preex import PreExSpecialist

ROSTER = {
    "RECON": ReconSpecialist,
    "SURFACE": SurfaceMapper,
    "PREEX": PreExSpecialist,
    "HYPOTHESES": HypothesisEngine,
    "EXPLOIT": ExploitSpecialist,
    "VERIFY": VerifySpecialist,
    "ACCESS": AccessSpecialist,
    "LOGIC": StatefuzzSpecialist,
    "WINDOW": WindowDriverSpecialist,
    "GRAPH": AttackGraphSpecialist,
}

__all__ = ["ROSTER", "ReconSpecialist", "SurfaceMapper", "PreExSpecialist",
           "HypothesisEngine",
           "ExploitSpecialist", "VerifySpecialist", "AccessSpecialist",
           "StatefuzzSpecialist", "WindowDriverSpecialist",
           "AttackGraphSpecialist"]
