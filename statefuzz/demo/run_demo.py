# -*- coding: utf-8 -*-
"""Phase-B demo driver: run statefuzz against the vulnerable and the fixed
build of vuln-bank and print the evidence.

    cd download && python -m statefuzz.demo.run_demo

Outputs (next to this file):
  demo-findings.json   vulnerable-run findings, findings.json schema
  demo-report.json     both run reports (vulnerable + fixed)
"""
from __future__ import annotations

import json
import os
import time

from ..context import Approvals, Bandit, ReferenceContext
from ..runner import statefuzz_run
from .vuln_bank import BANK_SPEC, DEMO_PRIORS, VULNERABLE_BUGS, BankApp

HERE = os.path.dirname(os.path.abspath(__file__))
ALL_TECHNIQUES = {"SF-SKIP", "SF-REPLAY", "SF-REORDER", "SF-PARTIAL",
                  "SF-NEGATIVE", "SF-CROSSUSER", "SF-RACE", "SF-IDEM"}


def make_ctx(app: BankApp) -> ReferenceContext:
    return ReferenceContext(
        adapter=app.adapter, observe=app.observe,
        approvals=Approvals(granted_techniques=set(ALL_TECHNIQUES)),
        bandit=Bandit(priors=dict(DEMO_PRIORS)),
    )


def main() -> None:
    t0 = time.time()

    print("=" * 72)
    print("statefuzz demo — vuln-bank, VULNERABLE build "
          f"(bugs={sorted(VULNERABLE_BUGS)})")
    print("=" * 72)
    vuln_app = BankApp(bugs=set(VULNERABLE_BUGS))
    vuln_ctx = make_ctx(vuln_app)
    vuln_report = statefuzz_run(vuln_ctx, budget=300, spec=BANK_SPEC)
    print(f"mutants: {vuln_report.mutants_total} total, "
          f"{vuln_report.mutants_executed} executed, "
          f"{vuln_report.mutants_skipped_unapproved} skipped (unapproved)")
    print(f"requests spent: {vuln_report.spent}/{300}   "
          f"violations: {vuln_report.violations_count}   "
          f"findings: {vuln_report.findings_count}   "
          f"({vuln_report.duration_s:.2f}s)")
    print("technique yield:",
          json.dumps(vuln_report.technique_yield, sort_keys=True))
    classes = sorted({f.invariant_class for f in vuln_ctx.findings})
    print("invariant classes hit:", ", ".join(classes))
    print()
    for f in vuln_ctx.findings[:8]:
        print(f"  [{f.finding_id}] {f.severity_hint:8s} {f.technique_id:12s} "
              f"{f.invariant_id}: {f.detail[:86]}")
    if len(vuln_ctx.findings) > 8:
        print(f"  ... +{len(vuln_ctx.findings) - 8} more")
    print()
    print("top impact chains (findings-as-capabilities):")
    for c in vuln_report.chains[:3]:
        print(f"  score {c['score']:.1f}: {' -> '.join(c['findings'])}")

    print()
    print("=" * 72)
    print("statefuzz demo — vuln-bank, FIXED build (bugs={})")
    print("=" * 72)
    fixed_app = BankApp(bugs=set())
    fixed_ctx = make_ctx(fixed_app)
    fixed_report = statefuzz_run(fixed_ctx, budget=300, spec=BANK_SPEC)
    print(f"mutants: {fixed_report.mutants_total} total, "
          f"{fixed_report.mutants_executed} executed   "
          f"violations: {fixed_report.violations_count}   "
          f"findings: {fixed_report.findings_count}   "
          f"({fixed_report.duration_s:.2f}s)")
    verdict = "PASS — zero findings on the fixed build (oracle precision)"
    if fixed_report.findings_count:
        verdict = "FAIL — false positives on the fixed build"
    print(verdict)

    with open(os.path.join(HERE, "demo-findings.json"), "w") as fh:
        json.dump({"findings": [f.to_dict() for f in vuln_ctx.findings]}, fh, indent=2)
    with open(os.path.join(HERE, "demo-report.json"), "w") as fh:
        json.dump({"vulnerable": vuln_report.to_dict(),
                   "fixed": fixed_report.to_dict()}, fh, indent=2)
    vuln_ctx.write_traffic(os.path.join(HERE, "demo-traffic.jsonl"))
    print(f"\nwrote demo-findings.json, demo-report.json, demo-traffic.jsonl "
          f"in {time.time() - t0:.1f}s total")


if __name__ == "__main__":
    main()
