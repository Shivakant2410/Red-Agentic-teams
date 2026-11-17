#!/usr/bin/env python3
"""Render docs/hands-and-skills.md from the live registries (truthful by
construction — the doc is a rendering, never hand-maintained)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.hands import HANDS, SKILLS, TRUST_CLASSES  # noqa: E402
from redteam.orchestrator import ACCESS, EXPLOIT, LOGIC, RECON, VERIFY  # noqa: E402
from redteam.specialists import CLASS_SPECIALISTS  # noqa: E402

ROLE = {
    "recon": "surface mapping (orchestrator round)",
    "exploit": "prove vulnerabilities (orchestrator round / swarm)",
    "access": "press a confirmed foothold (orchestrator round)",
    "logic": "business-logic workflows (orchestrator round)",
    "verify": "independent pass over pending findings",
}
for spec in CLASS_SPECIALISTS:
    ROLE[spec.profile.name] = f"OWASP {spec.owasp} {spec.title} (swarm class expert)"

out = []
out.append("# Hands and skills — what every agent holds and may execute\n")
out.append("> Rendering of `redteam/hands.py` (regenerate: `python3 scripts/gen_hands_doc.py`).")
out.append("Trust classes are the crosscheck layer's own vocabulary "
           "(`redteam/tools/crosscheck.py`); a hand may not claim a discipline the "
           "trust matrix does not enforce — `tests/test_hands.py` locks this.\n")
out.append("| Agent | Role | Hands | Skills |")
out.append("|---|---|---|---|")
for a in HANDS:
    out.append(f"| `{a}` | {ROLE.get(a, '-')} | {len(HANDS[a])} | {len(SKILLS.get(a, ()))} |")
out.append("")
out.append("Trust classes: " + ", ".join(f"`{c}`" for c in sorted(TRUST_CLASSES)) + "\n")

for a, hands in HANDS.items():
    out.append(f"\n## {a} — {ROLE.get(a, '')}\n")
    out.append("### Hands\n")
    out.append("| Tool | Cost | Trust | Purpose | Obligation |")
    out.append("|---|---|---|---|---|")
    for h in hands:
        purpose = h.purpose.replace("|", "/")
        obl = h.obligation.replace("|", "/")
        out.append(f"| `{h.tool}` | {h.cost} | {h.trust} | {purpose} | {obl} |")
    skills = SKILLS.get(a, ())
    out.append("\n### Skills\n")
    if not skills:
        out.append("(none declared)\n")
        continue
    for s in skills:
        out.append(f"**{s.name}** — WHEN {s.when}\n")
        for i, step in enumerate(s.steps, 1):
            out.append(f"{i}. {step}")
        out.append(f"\n- EXIT: {s.exit}")
        out.append(f"- PROOF: {s.proof}\n")

doc = "\n".join(out) + "\n"
path = Path("/home/z/my-project/repo-analysis/docs/hands-and-skills.md")
path.write_text(doc, encoding="utf-8")
print(f"wrote {path} ({len(doc.splitlines())} lines)")
