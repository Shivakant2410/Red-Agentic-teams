"""Benchmark runner: stand up a target, run the agent against it, score the result.

This is the thin orchestration around the (tested) scorer. It starts the vulnerable
container, waits for it to answer, writes a scoped engagement file for localhost, runs
the CLI, then scores findings.json against the target's ground truth.

    python -m redteam.bench.runner --target juice-shop --out runs/bench-js \
        --objective "Find and confirm injection, IDOR, XSS, and access-control issues"

Requires Docker and OPENROUTER_API_KEY. The scorer itself is unit-tested; this runner is
integration glue that needs live infrastructure.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path

import yaml

from .scoring import score_run
from .targets import get_target


def _wait_for(url: str, timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status < 500:
                    return True
        except Exception:
            time.sleep(2)
    return False


def _write_engagement(target, path: Path) -> None:
    doc = {
        "name": f"Benchmark: {target.name}", "client": "self", "authorized_by": "self",
        "ticket": "local-benchmark",
        "starts": time.strftime("%Y-%m-%d"), "ends": "2099-01-01",
        "scope": {
            "allowed_hosts": ["localhost", "127.0.0.1"],
            "allowed_ports": [target.host_port, 80, 443],
            "allowed_schemes": ["http", "https"],
            "allow_private_ranges": True,   # localhost is a private/loopback address
        },
        "objective": target.objective,      # the red-team scoreboard for this target
        "limits": {"max_requests_per_second": 20, "max_total_requests": 5000,
                   "max_run_seconds": 1800},
        # Genuinely-agentic on a FREE model: route the reasoning step to a large free
        # model (NVIDIA Nemotron 550B) instead of the tiny default. Parsing/triage stay
        # on the free small pool; the free pool is the fallback if this errors.
        "llm": {"role_models": {"plan": "nvidia/nemotron-3-ultra-550b-a55b:free",
                                "poc": "nvidia/nemotron-3-ultra-550b-a55b:free"}},
        # Localhost target: the Kali container can't reach the host's localhost, so we run
        # the browser + host-side confirm path (no Kali build needed for a benchmark).
        "sandbox": {"enable": False},
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def run(target_name: str, out: str, objective: str, multi_agent: bool = False) -> dict:
    target = get_target(target_name)
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    container = f"bench-{target_name}"

    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    print(f"Starting target {target.name} ...")
    proc = subprocess.run(target.docker_run(container), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"failed to start target: {proc.stderr}")

    try:
        if not _wait_for(target.base_url):
            raise RuntimeError(f"target did not become ready at {target.base_url}")

        eng_path = out_dir / "engagement.yaml"
        _write_engagement(target, eng_path)

        started = time.time()
        cmd = ["python", "-m", "redteam.cli", "--engagement", str(eng_path),
               "--objective", objective, "--out", str(out_dir),
               "--no-sandbox", "--yes-to-all", "--max-steps", "70"]
        if multi_agent:
            cmd.append("--multi-agent")
        subprocess.run(cmd, check=False)
        elapsed = time.time() - started
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)

    findings_path = out_dir / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.exists() else []
    manifest_path = out_dir / "manifest.json"
    tokens = 0
    if manifest_path.exists():
        tokens = json.loads(manifest_path.read_text(encoding="utf-8")).get("tokens", 0)

    # --- PRIMARY: the red-team scoreboard (objective reached, by what path) ---
    from ..access import AccessGraph
    from ..objective import Objective
    from .objective_scoring import score_objective_run

    objective = Objective.load(out_dir / "objective.json")
    access = AccessGraph(out_dir / "access.json") if (out_dir / "access.json").exists() else None
    steps = actions = 0
    audit_path = out_dir / "audit.log.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line).get("event", "")
            except json.JSONDecodeError:
                continue
            if ev == "agent.turn":
                steps += 1
            if ev.startswith(("http_request", "browser.", "sandbox.exec", "template.apply",
                              "apply_skill", "verify_vuln", "confirm.")):
                actions += 1
    confirmed = len([f for f in findings
                     if f.get("confidence") == "confirmed" and f.get("severity") != "info"])

    objective_card = score_objective_run(target.name, objective, access, steps=steps,
                                         elapsed_s=elapsed, tokens=tokens, actions=actions,
                                         confirmed_findings=confirmed)

    # --- SECONDARY: the old vulnerability-coverage view, explicitly demoted ---
    vuln_card = score_run(target.name, findings, target.ground_truth,
                          cost_tokens=tokens, elapsed_s=elapsed)

    report = (objective_card.to_markdown()
              + "\n\n---\n\n#### Secondary: vulnerability coverage (not the goal)\n\n"
              + vuln_card.to_markdown())
    (out_dir / "scorecard.md").write_text(report, encoding="utf-8")
    print(report)
    return {"objective_achieved": objective_card.achieved,
            "completion": objective_card.completion,
            "precision": vuln_card.precision, "recall": vuln_card.recall}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the agent against a benchmark target and score it.")
    ap.add_argument("--target", required=True, help="e.g. juice-shop, dvwa")
    ap.add_argument("--out", default="runs/bench")
    ap.add_argument("--objective",
                    default="Find and CONFIRM real vulnerabilities. Do a quick map, then "
                            "immediately start proving bugs: use confirm_finding for injection/XSS, "
                            "authenticate then test_idor for IDOR, and test_access_control for "
                            "broken access control. Prioritize confirming findings over browsing. "
                            "When one lands, chain it. Only confirmed findings count.")
    ap.add_argument("--multi-agent", action="store_true",
                    help="Drive the run with the orchestrator + specialist swarm.")
    args = ap.parse_args(argv)
    run(args.target, args.out, args.objective, multi_agent=args.multi_agent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
