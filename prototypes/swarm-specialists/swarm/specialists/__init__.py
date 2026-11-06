"""Specialist roster — one specialist per engagement state."""
from .recon import ReconSpecialist
from .surface_mapper import SurfaceMapper
from .hypothesis import HypothesisEngine
from .exploit import ExploitSpecialist
from .verify import VerifySpecialist
from .access import AccessSpecialist
from .statefuzz_spec import StatefuzzSpecialist
from .window_driver import WindowDriverSpecialist

ROSTER = {
    "RECON": ReconSpecialist,
    "SURFACE": SurfaceMapper,
    "HYPOTHESES": HypothesisEngine,
    "EXPLOIT": ExploitSpecialist,
    "VERIFY": VerifySpecialist,
    "ACCESS": AccessSpecialist,
    "LOGIC": StatefuzzSpecialist,
    "WINDOW": WindowDriverSpecialist,
}

__all__ = ["ROSTER", "ReconSpecialist", "SurfaceMapper", "HypothesisEngine",
           "ExploitSpecialist", "VerifySpecialist", "AccessSpecialist",
           "StatefuzzSpecialist", "WindowDriverSpecialist"]
