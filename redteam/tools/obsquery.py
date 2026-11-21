"""observations — the agent's read side of the run's observation log.

Query the provenance/validation record every recon tool writes into: what is
known, from which source, whether it is corroborated or still an unverified
lead, and what was contradicted. Read-only, no budget cost. This is how a
specialist avoids repeating another specialist's discovery work — check here
BEFORE running the same discovery tool again.
"""
from __future__ import annotations

import json

from . import ToolContext


class ObservationsTool:
    """observations — query/filter the run's observation log."""

    name = "observations"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Search the run's observation log: every recon claim recorded "
                "so far (endpoints, parameters, technologies, hosts, domains, "
                "forms, headers, console errors) with its SOURCE tool, mode "
                "(passive/light/active), timestamp and VALIDATION state "
                "(discovered | awaiting_corroboration | corroborated | "
                "contradicted | unverifiable | stale). Call BEFORE re-running "
                "any discovery tool — re-discovering what another specialist "
                "already recorded wastes steps. 'validation=discovered' lists "
                "leads that still need a second method (crosscheck_lead)."),
            "input_schema": {
                "type": "object",
                "properties": {
                    "type": {"type": "string",
                             "description": "endpoint | parameter | technology | "
                                            "host | domain | service | form | "
                                            "header | api_spec | console_error | asset"},
                    "validation": {"type": "string",
                                   "description": "discovered | awaiting_corroboration | "
                                                  "corroborated | contradicted | "
                                                  "unverifiable | stale"},
                    "mode": {"type": "string",
                             "description": "passive | light | active"},
                    "target_contains": {"type": "string"},
                    "stats_only": {"type": "boolean",
                                   "description": "return aggregate counts only"},
                    "limit": {"type": "integer"},
                },
            },
        }

    def run(self, ctx, obs_type: str = "", validation: str = "", mode: str = "",
            target_contains: str = "", stats_only: bool = False,
            limit=None) -> str:
        observations = getattr(ctx, "observations", None)
        if observations is None:
            return ("Observation log not wired in this run (legacy path); "
                    "discovery results live in graph.json/inventory.json only.")
        if stats_only:
            return json.dumps({"stats": observations.stats()})
        try:
            limit_i = int(limit) if limit else 50
        except (TypeError, ValueError):
            limit_i = 50
        rows = observations.filter(obs_type=str(obs_type or ""),
                                   validation=str(validation or ""),
                                   mode=str(mode or ""),
                                   target_contains=str(target_contains or ""),
                                   limit=limit_i)
        return json.dumps({"count": len(rows), "rows": rows,
                           "stats": observations.stats()})
