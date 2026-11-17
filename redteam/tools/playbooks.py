"""find_techniques — the offline technique library (agents look it up, never search).

The operator direction behind Phase D0: agents should not burn budget rediscovering
known tradecraft on the web. This tool is the missing research layer between
`find_attack_templates` (community CVE templates, needs the cloned nuclei corpus)
and the earned skill library (only what has actually proven out on a target):

  find_attack_templates -> community templates for a FINGERPRINTED product
  find_techniques (this) -> first-party playbooks for a TECHNIQUE CLASS, always here
  skills (apply_skill)   -> proofs already earned on some target

The corpus ships IN THE REPO under `data/playbooks/` — offline by construction, no
clone step. Every playbook is structured (kill-chain phase, surfaces, risk class,
concrete steps naming THIS platform's tools, a verify_hint that feeds the proof
pipeline, and an honest detection_risk tag that the B4 harness can measure).

Egress discipline note baked into the schema: steps that need third-party data
sources (crt.sh, wayback dumps, leak corpora) are marked `data_source: operator` —
the sandbox egress firewall would refuse them anyway, so the playbook says who
fetches what instead of teaching the agent to try and fail.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import ToolContext

DEFAULT_PLAYBOOK_ROOT = Path(__file__).resolve().parents[2] / "data" / "playbooks"

KILL_CHAIN_PHASES = ("recon", "surface", "enum", "exploit", "creds", "postex",
                     "lateral", "report")
RISK_CLASSES = (0, 1, 2, 3, 4)
DETECTION_RISKS = ("none", "low", "medium", "high", "unmeasured")
SURFACES = ("web", "api", "ad", "cloud", "k8s", "host")

_WORD = re.compile(r"[a-z0-9]+")
_ID = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_TOOL = re.compile(r"^[a-z0-9_]+$")          # tool names use snake_case
_MAX_LIMIT = 8


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


def load_playbooks(root: Path) -> list[dict]:
    """Load + validate the corpus. Raises ValueError with the offending file named —
    this doubles as the corpus linter in CI."""
    if not root.exists():
        raise ValueError(f"playbook corpus missing: {root}")
    import yaml
    playbooks: list[dict] = []
    seen: set[str] = set()
    for path in sorted(root.glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as exc:
            raise ValueError(f"{path.name}: invalid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError(f"{path.name}: not a mapping")
        for field in ("id", "name", "kill_chain", "surfaces", "risk_class",
                      "technique", "verify_hint"):
            # `is None`, not falsy — risk_class 0 is valid and falsy.
            if doc.get(field) is None:
                raise ValueError(f"{path.name}: missing required field '{field}'")
        pid = str(doc["id"])
        if not _ID.match(pid):
            raise ValueError(f"{path.name}: bad id '{pid}' (lowercase-hyphen only)")
        if pid in seen:
            raise ValueError(f"{path.name}: duplicate id '{pid}'")
        seen.add(pid)
        if doc["kill_chain"] not in KILL_CHAIN_PHASES:
            raise ValueError(f"{path.name}: kill_chain must be one of {KILL_CHAIN_PHASES}")
        if doc["risk_class"] not in RISK_CLASSES:
            raise ValueError(f"{path.name}: risk_class must be one of {RISK_CLASSES}")
        surfaces = doc["surfaces"]
        if not isinstance(surfaces, list) or not surfaces or \
                any(s not in SURFACES for s in surfaces):
            raise ValueError(f"{path.name}: surfaces must be a non-empty subset of {SURFACES}")
        if doc.get("detection_risk") and doc["detection_risk"] not in DETECTION_RISKS:
            raise ValueError(f"{path.name}: detection_risk must be one of {DETECTION_RISKS}")
        if not isinstance(doc["technique"], str) or len(doc["technique"]) < 80:
            raise ValueError(f"{path.name}: 'technique' must be concrete steps "
                             f"(>= 80 chars), not a stub")
        for tool in doc.get("tools", []) or []:
            if not _TOOL.match(str(tool)):
                raise ValueError(f"{path.name}: bad tool name '{tool}'")
        playbooks.append(doc)
    if not playbooks:
        raise ValueError(f"{root}: no playbooks found")
    return playbooks


def _score(p: dict, q_tokens: set[str], tag_tokens: dict[str, float]) -> float:
    doc = _tokens(p["id"] + " " + p["name"] + " " + " ".join(p.get("tech_tags", []))
                  + " " + " ".join(p.get("tools", [])) + " " + p["technique"][:400])
    score = 0.0
    for t in q_tokens & doc:
        score += tag_tokens.get(t, 1.0)
    # A query token that names one of the playbook's tools is a strong signal.
    tool_tokens = _tokens(" ".join(p.get("tools", [])))
    for t in q_tokens & tool_tokens:
        score += 2.0
    return score


class FindTechniquesTool:
    name = "find_techniques"

    def schema(self) -> dict:
        return {
            "name": self.name,
            "description": (
                "RESEARCH step, offline: look up first-party technique playbooks for "
                "the phase you are working (recon/surface/enum/exploit/creds/postex/"
                "lateral/report) and the surface (web/api/ad/cloud/k8s/host). Returns "
                "CONCRETE steps naming the platform's tools, a verify_hint that feeds "
                "the proof pipeline, the playbook's risk class, and an honest "
                "detection_risk tag. Use this BEFORE inventing an approach or "
                "searching the web — if the playbook list has nothing, it says so and "
                "you design your own probe through verify_vulnerability."
            ),
            "input_schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kill_chain": {"type": "string", "enum": list(KILL_CHAIN_PHASES),
                                   "description": "Phase you are working in."},
                    "surface": {"type": "string", "enum": list(SURFACES),
                                "description": "Target surface (web, api, ad, cloud, k8s, host)."},
                    "query": {"type": "string",
                              "description": "Optional technique terms ('template injection', "
                                             "'kerberoast', 'hidden params')."},
                    "limit": {"type": "integer", "description": "Max playbooks (default 3, max 8)."},
                },
                "required": ["kill_chain"],
            },
            "strict": True,
        }

    def run(self, ctx: ToolContext, kill_chain: str, surface: str = "",
            query: str = "", limit: int = 3) -> str:
        root = Path(getattr(ctx, "playbook_root", None) or DEFAULT_PLAYBOOK_ROOT)
        try:
            playbooks = load_playbooks(root)
        except ValueError as exc:
            ctx.audit.record("technique.search.error", error=str(exc)[:200])
            return json.dumps({"ok": False, "error": str(exc)})

        if kill_chain not in KILL_CHAIN_PHASES:
            return json.dumps({"ok": False,
                               "error": f"kill_chain must be one of {KILL_CHAIN_PHASES}"})

        pool = [p for p in playbooks if p["kill_chain"] == kill_chain]
        if surface:
            pool = [p for p in pool if surface in p["surfaces"]]

        limit = max(1, min(int(limit), _MAX_LIMIT))
        q_tokens = _tokens(query)
        tag_tokens = {t: 1.5 for t in q_tokens}
        scored = sorted(((_score(p, q_tokens, tag_tokens), p["id"]) for p in pool),
                        key=lambda t: (-t[0], t[1]))
        picked = [(s, pid) for s, pid in scored if not q_tokens or s > 0] or scored
        results = []
        for _, pid in picked[:limit]:
            p = next(x for x in pool if x["id"] == pid)
            results.append({
                "id": p["id"], "name": p["name"], "kill_chain": p["kill_chain"],
                "surfaces": p["surfaces"], "risk_class": p["risk_class"],
                "tools": p.get("tools", []), "prerequisites": p.get("prerequisites", []),
                "detection_risk": p.get("detection_risk", "unmeasured"),
                "steps": p["technique"], "verify_hint": p["verify_hint"],
                "references": p.get("references", []),
            })

        ctx.audit.record("technique.search", kill_chain=kill_chain, surface=surface,
                         query=query, results=len(results))

        if not results:
            # Never leave the agent empty-handed: hand back the phase index so it
            # knows what IS available before reaching for the web.
            by_chain = {c: sum(1 for x in playbooks if x["kill_chain"] == c)
                        for c in KILL_CHAIN_PHASES}
            return json.dumps({
                "ok": True, "results": [], "corpus_index": by_chain,
                "note": ("No playbook matches in this phase/surface. Design your own "
                         "probe via http_probe + verify_vulnerability, or ask the "
                         "operator — do not search the web from the sandbox; egress "
                         "is restricted to in-scope targets."),
            }, ensure_ascii=False)

        return json.dumps({
            "ok": True, "results": results,
            "note": ("Steps are a starting map, not a license: every proof still goes "
                     "through verify_vulnerability / verify_finding_independently, "
                     "and each tool's own risk-class gate still applies."),
        }, ensure_ascii=False)
