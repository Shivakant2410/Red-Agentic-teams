"""python -m redteam.sc — the LLM03 lane's audit surface.

Two deterministic, offline audits; no run mode lives here (the fixture
runner is import-level, redteam/sc/runner.py):

  --audit   the registry coverage audit: techniques, payload (spec)
            counts, family layout, and the named known-uncovered
            boundaries — including the explicit mapping statements
            (post-training ROME vs T0020).
  --atlas   the ATLAS-side catalog, the two-way map derived from the
            registry's own anchors, the coverage audit (exercised vs
            uncovered), candidate anchors, and the verification
            statement.

The numbers NEVER mix with the live lanes: everything here is computed
from frozen, verified facts.
"""

from __future__ import annotations

import argparse
import json


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="python -m redteam.sc",
        description="OWASP LLM03:2025 Supply Chain lane audits "
                    "(offline, deterministic)")
    ap.add_argument("--audit", action="store_true",
                    help="print the registry coverage audit")
    ap.add_argument("--atlas", action="store_true",
                    help="print the ATLAS-side catalog, two-way map and "
                         "coverage audit")
    args = ap.parse_args()

    if args.atlas:
        from .atlas import atlas_audit
        print(json.dumps(atlas_audit(), indent=2, ensure_ascii=False))
        return 0
    if args.audit:
        from .techniques import coverage_audit
        print(json.dumps(coverage_audit(), indent=2, ensure_ascii=False))
        return 0
    ap.error("one of --audit or --atlas is required")


if __name__ == "__main__":
    raise SystemExit(main())
