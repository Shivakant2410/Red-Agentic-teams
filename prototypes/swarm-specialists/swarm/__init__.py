"""swarm — specialist-swarm orchestration layer (Phase C).

build_swarm_registry() -> {"swarm_run": {schema(), run(ctx)}}
"""
__version__ = "0.1.0"

import os
import sys

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)   # vendored Phase-B statefuzz package

from .registry_tool import build_swarm_registry, run  # noqa: E402,F401


def build_registry():
    return build_swarm_registry()
