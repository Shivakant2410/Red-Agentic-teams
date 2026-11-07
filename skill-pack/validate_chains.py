"""Validate the attack-chain tree (chains/<group>/<slug>.json).

Standalone structural validation — no repo machinery needed:

  C1  schema: required keys present, slug == file stem, unique slugs
  C2  steps: 1..N sequential; every `skill` is an exact installed skill name in
      categories/; purpose/on_success/on_fail non-empty
  C3  discovery: entry_points/recon/variants/dorks/pivot_hints present and
      populated (recon >= 4 with name/how/tooling/signal, variants >= 4,
      dorks >= 2, sources >= 3)
  C4  graph: fallbacks reference existing chain slugs, never self

Writes chains_validation_report.txt and exits non-zero on any violation.

Usage: python3 validate_chains.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
CATS = BASE / "categories"
CHAINS = BASE / "chains"

REQUIRED_CHAIN_KEYS = ["slug", "name", "goal", "preconditions", "cwe", "impact",
                       "steps", "discovery", "fallbacks", "sources"]
REQUIRED_DISCOVERY_KEYS = ["entry_points", "recon", "variants", "dorks", "pivot_hints"]
REQUIRED_STEP_KEYS = ["n", "skill", "purpose", "on_success", "on_fail"]
# NOTE: no "{{" mark here on purpose — chains legitimately QUOTE payload and
# template syntax in prose (e.g. the {{7*7}} SSTI canary, {{role_name}} param
# hand-off). The strict "no unfilled template" gate lives in
# validate_skill_pack.py G2 and applies to skill JSONs, not chain prose.
PLACEHOLDER_MARKS = ["TODO", "XXX", "待补充", "【"]


def main() -> int:
    skill_names = {json.loads(p.read_text(encoding="utf-8"))["name"]
                   for p in CATS.glob("*/*.json")}

    errors: list[str] = []
    chains: dict[str, dict] = {}
    files = sorted(CHAINS.glob("*/*.json"))
    for path in files:
        ch = json.loads(path.read_text(encoding="utf-8"))
        tag = str(path.relative_to(BASE))
        slug = ch.get("slug", "")
        if slug != path.stem:
            errors.append(f"{tag}: slug '{slug}' != file stem '{path.stem}'")
        if slug in chains:
            errors.append(f"{tag}: duplicate slug {slug}")
        chains[slug] = ch
        for k in REQUIRED_CHAIN_KEYS:
            if not ch.get(k):
                errors.append(f"{tag}: missing/empty key {k}")
        for mark in PLACEHOLDER_MARKS:
            if mark in json.dumps(ch):
                errors.append(f"{tag}: placeholder residue '{mark}'")

        steps = ch.get("steps") or []
        for i, step in enumerate(steps, start=1):
            if step.get("n") != i:
                errors.append(f"{tag}: step numbering broken at {i}")
            if step.get("skill") not in skill_names:
                errors.append(f"{tag} step {i}: unknown skill "
                              f"'{step.get('skill')}'")
            for k in REQUIRED_STEP_KEYS:
                if not step.get(k):
                    errors.append(f"{tag} step {i}: empty {k}")

        disc = ch.get("discovery") or {}
        for k in REQUIRED_DISCOVERY_KEYS:
            if not disc.get(k):
                errors.append(f"{tag}: discovery.{k} missing/empty")
        for rc in disc.get("recon") or []:
            for k in ("name", "how", "tooling", "signal"):
                if not rc.get(k):
                    errors.append(f"{tag}: recon entry missing {k}")
        if len(disc.get("recon") or []) < 4:
            errors.append(f"{tag}: fewer than 4 recon methods")
        if len(disc.get("variants") or []) < 4:
            errors.append(f"{tag}: fewer than 4 variants")
        if len(disc.get("dorks") or []) < 2:
            errors.append(f"{tag}: fewer than 2 dorks")
        if len(ch.get("sources") or []) < 3:
            errors.append(f"{tag}: fewer than 3 sources")
        if not ch.get("cwe"):
            errors.append(f"{tag}: no CWE tag")

    for slug, ch in chains.items():
        for fb in ch.get("fallbacks") or []:
            if fb == slug:
                errors.append(f"{slug}: self fallback")
            elif fb not in chains:
                errors.append(f"{slug}: fallback '{fb}' is not a chain slug")

    groups = sorted({p.parent.name for p in files})
    total_skills = len({s["skill"] for ch in chains.values()
                        for s in ch["steps"] if s.get("skill") in skill_names})

    lines = [f"chains validated: {len(files)} files, {len(chains)} slugs, "
             f"{len(groups)} groups, {total_skills} distinct skills referenced",
             f"skill registry: {len(skill_names)} installed skills"]
    if errors:
        lines += [f"VIOLATIONS ({len(errors)}):"] + [f"  - {e}" for e in errors]
    else:
        lines.append("RESULT: PASS — all chain gates (C1-C4) clean")
    report = "\n".join(lines) + "\n"
    (BASE / "chains_validation_report.txt").write_text(report, encoding="utf-8")
    print(report)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
