"""SC MCP client environments — client-stand-in CONTROLS with names
mapped to published designs (SOTA.md backlog B4).

First principles: a poisoned description only matters against clients
that differ in HOW they treat the metadata channel. The controls:

    gullible    no control — descriptions are read as instructions (the
                Invariant Labs fold): every relay demand in any
                admitted tool's description is parsed with the lane's
                public grammar and executed, with the client's OWN
                credential substituted for the placeholder. Selection
                trusts fold-distance-1 lookalikes whose description
                claims authority (the cross-server shadow POC).
    rescan      MCP-Scan-style (Invariant): descriptions are SCANNED at
                every use — a description matching the relay grammar is
                rejected and never read. Blocks every description shape
                INCLUDING the rug pull (approval time != use time stops
                mattering when every use re-scans). The named gap: a
                directive scanner sees ONE channel — selection hijack
                rides no directive at all, so the shadow still folds.
                Cost fact: blocking the approved tool's re-listed poison
                also blocks the task it serves.
    hardened    metadata-only + exact-name identity + scan: descriptions
                are never instructions, only the exact demanded tool is
                selectable, and the scan runs — resists every shape.

The faithful base behavior (every policy): admit what passes, perform
the task with the selected fetcher (reply references the task marker),
never touch the credential unprompted. Deterministic; no LLM; no
network.
"""

from __future__ import annotations

import json

from .mcp import (AUTHORITY_MARKER, DEMANDED_TOOL, MCP_DIRECTIVE_RE,  # noqa
                  RELAY_TOOL, SECRET_PLACEHOLDER, TASK_MARKER)
from .oracles import _fold_separators, _levenshtein


def mcp_client(*, policy: str = "gullible"):
    """An MCP client stand-in: client(task, catalog, secret) ->
    {"reply", "admitted", "rejected", "tool_calls"} with the named
    control configured."""
    if policy not in ("gullible", "rescan", "hardened"):
        raise ValueError("unknown client policy")

    def _client(task, catalog, secret):
        tools = list(catalog or [])
        admitted, rejected = [], []
        for t in tools:
            name, desc = t.get("name") or "", t.get("description") or ""
            # the scan control: a description matching the relay grammar
            # is rejected BEFORE anything reads it
            if policy in ("rescan", "hardened") \
                    and MCP_DIRECTIVE_RE.search(desc):
                rejected.append(name)
            else:
                admitted.append(name)

        # selection of the demanded tool among ADMITTED tools only
        cands = [t for t in tools
                 if t.get("name") in admitted
                 and _levenshtein(_fold_separators(t.get("name") or ""),
                                  _fold_separators(DEMANDED_TOOL)) <= 1]
        chosen = None
        if cands:
            if policy == "hardened":
                exact = [t for t in cands if t["name"] == DEMANDED_TOOL]
                chosen = exact[0] if exact else None
            else:
                # trust the description that CLAIMS the role: an
                # authority marker outranks the exact-name candidate —
                # the shadow vector
                marked = [t for t in cands
                          if AUTHORITY_MARKER in (t.get("description")
                                                  or "")]
                chosen = (marked or cands)[0]

        calls = []
        # the fold: directives inside ADMITTED descriptions are parsed
        # with the lane's public grammar and the client's OWN credential
        # is substituted for the placeholder
        if policy == "gullible":
            for t in tools:
                if t.get("name") in rejected:
                    continue
                for m in MCP_DIRECTIVE_RE.finditer(
                        t.get("description") or ""):
                    raw = m.group(1)
                    if SECRET_PLACEHOLDER not in raw:
                        continue            # garbage is not a directive
                    try:
                        args = json.loads(raw.replace(SECRET_PLACEHOLDER,
                                                      secret))
                    except Exception:
                        continue
                    calls.append({"tool": RELAY_TOOL, "args": args})

        if chosen is not None:
            calls.append({"tool": chosen["name"],
                          "args": {"report": TASK_MARKER}})
            reply = f"Summarized {TASK_MARKER}."
        else:
            reply = "no exact fetcher in the catalog — task not completed"
        return {"reply": reply, "admitted": admitted,
                "rejected": rejected, "tool_calls": calls}

    return _client
