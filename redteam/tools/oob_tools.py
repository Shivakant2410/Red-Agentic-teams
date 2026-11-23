"""Agent-facing OOB tools: mint_canary / poll_canary.

The workflow for proving a BLIND vulnerability:
  1. mint_canary  -> a unique domain to embed in a payload (SSRF url, XXE
     entity, `nslookup $(cmd)`, XSS beacon src).
  2. fire the payload through the normal tools (http_probe, kali_exec, browser).
  3. poll_canary  -> did the target call back? (also readable by the
     oob_callback proof predicate for a reproducible CheckOutcome).

A confirmed finding still goes through confirm_finding with an oob_callback
condition, so a blind bug is proven by the SAME verify pipeline as everything
else — the agent never self-certifies a blind hit.
"""
from __future__ import annotations

import json

from . import ToolContext


class MintCanaryTool:
    name = "mint_canary"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Mint a unique out-of-band canary domain to embed in a payload "
                "when testing a BLIND vulnerability (blind SSRF/XXE, DNS exfil, "
                "blind XSS, async command execution). Fire the payload with the "
                "canary inside it, then poll_canary (or a confirm_finding "
                "oob_callback condition) to see if the TARGET called back — the "
                "only deterministic proof of a blind bug. Only place canaries in "
                "payloads aimed at IN-SCOPE targets."),
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "label": {"type": "string",
                              "description": "What you're testing (audited, e.g. 'ssrf on /fetch?url=')."},
                },
                "required": [],
            },
            "strict": False,
        }

    def run(self, ctx: ToolContext, label: str = "") -> str:
        oob = getattr(ctx, "oob", None)
        if oob is None:
            return ("ERROR: OOB oracle not available in this run. Set "
                    "RED_OOB_SERVER (self-hosted interactsh) or "
                    "RED_OOB_ENABLE_PUBLIC=1 to enable blind-vuln testing.")
        try:
            canary = oob.mint(label=label)
        except Exception as exc:  # OOBError and friends
            return f"ERROR: {exc}"
        return json.dumps({
            "canary": canary,
            "usage": ("embed this domain in your payload (http://<canary>/ for "
                      "SSRF, <canary> for DNS/XXE, //<canary>/x for XSS beacon), "
                      "fire it, then poll_canary — or add an oob_callback "
                      "condition {type:'oob_callback', canary:'<canary>'} to "
                      "confirm_finding."),
        })


class PollCanaryTool:
    name = "poll_canary"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "Poll the OOB oracle for interactions (DNS/HTTP callbacks) the "
                "target made to a canary you minted. Returns the interactions "
                "seen so far. Give a short delay after firing the payload — "
                "async callbacks can lag a few seconds."),
            "input_schema": {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "canary": {"type": "string",
                               "description": "The canary domain to check (from mint_canary)."},
                    "protocol": {"type": "string",
                                 "description": "Optional filter: 'dns' or 'http'."},
                },
                "required": ["canary"],
            },
            "strict": False,
        }

    def run(self, ctx: ToolContext, canary: str, protocol: str = "") -> str:
        oob = getattr(ctx, "oob", None)
        if oob is None:
            return "ERROR: OOB oracle not available in this run."
        hits = oob.interactions_for(canary, protocol=protocol)
        return json.dumps({
            "canary": canary,
            "interaction_count": len(hits),
            "interactions": [
                {"protocol": h.protocol, "remote_addr": h.remote_addr,
                 "ts": h.ts} for h in hits[:20]
            ],
            "proven": len(hits) > 0,
            "note": ("a callback here PROVES the target reached your canary — "
                     "record it with confirm_finding using an oob_callback "
                     "condition so it goes through independent verification."),
        })
