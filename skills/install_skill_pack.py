"""Install the skill catalog (category-folder tree) into a Red-Agentic-teams
memory_dir/skills.json.

Layout consumed:

    categories/<folder>/<slug>.json   — one Skill object per file

Uses the repo's own SkillLibrary.register() path (the bulk-import path built for
nuclei corpora), so the on-disk format is exactly what the platform writes itself.
Idempotent by NAME: a second run adds 0.

Two upstream quirks force a name-level guard here (recorded for the upstream fix):
  1. SkillLibrary dedupe signature is ASYMMETRIC — register() indexes by
     (name, conditions) but the loader indexes by (cwe, conditions), so a
     cwe-tagged skill loaded from disk is invisible to register()'s dedupe.
  2. register() ignores any supplied id and always mints a fresh uuid4 id,
     so pack ids cannot be used as the cross-install identity.

Usage:

    python3 install_skill_pack.py <memory_dir> [--only ssti,ssrf] [--list] [--no-chains]

Also installs the attack-chain tree: chains/<group>/<slug>.json is exported as a
single <memory_dir>/chains.json (planner artifact, not Skill objects) unless
--no-chains is given.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The pack lives inside the Red-Agentic-teams repo (skills/), so the repo root
# (which provides redteam/skills.py) is one level up. Override with
# RAT_REPO=/path/to/Red-Agentic-teams when running from a standalone pack copy.
_REPO = Path(os.environ.get("RAT_REPO") or Path(__file__).resolve().parent.parent)
sys.path.insert(0, str(_REPO))

from redteam.skills import SkillLibrary         # noqa: E402

BASE = Path(__file__).resolve().parent / "categories"
CHAINS_BASE = Path(__file__).resolve().parent / "chains"


def collect(only: list[str] | None = None) -> dict[str, list[dict]]:
    shelves: dict[str, list[dict]] = {}
    for fdir in sorted(BASE.iterdir()):
        if not fdir.is_dir():
            continue
        if only and fdir.name not in only:
            continue
        rows = []
        for jf in sorted(fdir.glob("*.json")):
            rows.append(json.loads(jf.read_text(encoding="utf-8")))
        if rows:
            shelves[fdir.name] = rows
    return shelves


def collect_chains() -> list[dict]:
    if not CHAINS_BASE.is_dir():
        return []
    rows = []
    for jf in sorted(CHAINS_BASE.glob("*/*.json")):
        rows.append(json.loads(jf.read_text(encoding="utf-8")))
    return rows


def main(argv: list[str]) -> int:
    only: list[str] | None = None
    listing = False
    with_chains = True
    for arg in argv[1:]:
        if arg == "--list":
            listing = True
        elif arg.startswith("--only="):
            only = arg.split("=", 1)[1].split(",")
        elif arg == "--only":
            idx = argv.index(arg)
            only = argv[idx + 1].split(",")
        elif arg == "--no-chains":
            with_chains = False
    if not listing and len(argv) < 2:
        print(__doc__)
        return 2

    shelves = collect(only)
    total = sum(len(r) for r in shelves.values())
    if listing:
        for folder, rows in shelves.items():
            print(f"{folder} ({len(rows)}):")
            for row in rows:
                print(f"  - {row['name']} [{row.get('cwe','')}]")
        print(f"total: {total} skills in {len(shelves)} shelves")
        return 0

    memory_dir = Path(argv[1])
    target = memory_dir / "skills.json"
    lib = SkillLibrary(target, max_skills=50000)
    before = lib.summary()["skills"]

    added, skipped = 0, 0
    known_names = {s.name for s in lib.all()}
    for folder, rows in shelves.items():
        f_added = 0
        for row in rows:
            if row["name"] in known_names:
                skipped += 1
                continue
            lib.register(
                name=row["name"], description=row["description"], cwe=row.get("cwe", ""),
                requests=row["requests"], conditions=row["conditions"],
                params=row.get("params") or [], source="imported", flush=False)
            known_names.add(row["name"])
            added += 1
            f_added += 1
        print(f"  {folder}: +{f_added}")
    lib.flush()

    after = SkillLibrary(target).summary()["skills"]
    print(f"{target}: {before} existing -> {added} added, {skipped} already known, "
          f"{after} total (catalog: {total} skills / {len(shelves)} shelves)")

    if with_chains:
        chains = collect_chains()
        chains_path = memory_dir / "chains.json"
        chains_path.write_text(json.dumps(chains, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(f"{chains_path}: {len(chains)} attack chains exported "
              f"(planner artifact; groups: "
              f"{', '.join(sorted({c.get('group', '') for c in chains}))})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
