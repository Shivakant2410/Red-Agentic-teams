"""Benchmark runner: stand up a target, run the agent against it, score the result.

This is the thin orchestration around the (tested) scorer. It starts the vulnerable
container, joins it to the Kali sandbox's own Docker network so kali_exec tools
(nmap/ffuf/sqlmap/nikto/gobuster) can actually reach it, waits for it to answer, writes a
scoped engagement file, runs the CLI WITH the sandbox enabled, then scores findings.json
against the target's ground truth.

    python -m redteam.bench.runner --target juice-shop --out runs/bench-js \
        --objective "Find and confirm injection, IDOR, XSS, and access-control issues"

    # Positive run + negative control on the same app (lab/), scored together:
    python -m redteam.bench.runner --target lab-authz --out runs/bench-lab

Requires Docker and OPENROUTER_API_KEY. The scorer itself is unit-tested; this runner is
integration glue that needs live infrastructure.

WHY THIS MATTERS (fixed after it was found and flagged): every benchmark run before this
disabled the Kali sandbox entirely, because `localhost` means nothing from inside a
separate container — the Kali container and the target container were never on the same
Docker network, so kali_exec's whole toolset went unused and every run fell back to the
browser/host-requests path only. This runner now puts the target on redteam-net (the
same network KaliSandbox creates) and points the engagement at the target's actual
container IP on that network (resolved via `docker inspect`, since a container name only
resolves via Docker's embedded DNS INSIDE a container on that network — the host process
running this script can't resolve it, so an IP literal is used instead, which both
ScopeGuard and build_egress_plan already handle directly with no resolution needed).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml
from dotenv import find_dotenv, load_dotenv

from ..config import SandboxConfig
from .scoring import score_pair, score_run
from .targets import LAB_OBJECTIVE_PROMPT, PAIRS, REGISTRY, get_target

REDTEAM_NETWORK = SandboxConfig().network_name   # "redteam-net" — must match KaliSandbox's


def _ensure_network(name: str = REDTEAM_NETWORK) -> None:
    proc = subprocess.run(["docker", "network", "inspect", name], capture_output=True)
    if proc.returncode != 0:
        subprocess.run(["docker", "network", "create", name], capture_output=True)


def _container_ip_on_network(container: str, network: str = REDTEAM_NETWORK) -> str:
    """Resolve a running container's IP on `network` via docker inspect — not DNS, which
    only works from inside a container on that network, never from this host process."""
    proc = subprocess.run(
        ["docker", "inspect", "-f",
         "{{(index .NetworkSettings.Networks \"" + network + "\").IPAddress}}", container],
        capture_output=True, text=True)
    ip = proc.stdout.strip()
    if proc.returncode != 0 or not ip:
        raise RuntimeError(
            f"could not resolve {container!r}'s IP on network {network!r}: {proc.stderr}")
    return ip


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


# Per-role model plan. The binding constraint is OpenRouter's free tier (50 requests/day
# without credit), and a swarm run needs hundreds of calls: high-volume roles go to the
# Ollama cloud flash model, the scarce OpenRouter quota goes to low-volume reasoning
# (logic, workflow verification, single-agent plan/poc). Pins naming a provider that
# isn't enabled are dropped; each role still falls back to its provider pools.
_CLOUD_FLASH = "ollama:minimax-m3.1-flash:cloud"
_OR_ULTRA = "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free"
_OR_INKLING = "openrouter:thinkingmachines/inkling:free"
_OR_LIGHTNING = "openrouter:nvidia/nemotron-3.5-lightning:free"
_ROLE_PLAN = {
    "recon":   [_CLOUD_FLASH, _OR_LIGHTNING],
    "exploit": [_CLOUD_FLASH, _OR_ULTRA],
    "access":  [_CLOUD_FLASH, _OR_LIGHTNING],
    "logic":   [_OR_INKLING, _OR_ULTRA, _CLOUD_FLASH],
    "verify":  [_OR_ULTRA, _OR_INKLING],
    "plan":    [_OR_ULTRA, _CLOUD_FLASH],
    "poc":     [_OR_ULTRA, _CLOUD_FLASH],
}


def _llm_block(providers: tuple[str, ...], ollama_models: str) -> dict:
    block = {"providers": list(providers), "ollama_models": ollama_models}
    role_models = {}
    for role, pins in _ROLE_PLAN.items():
        kept = [p for p in pins if p.split(":", 1)[0] in providers]
        if kept:
            role_models[role] = kept
    if role_models:
        block["role_models"] = role_models
    return block


def _default_max_run_seconds(providers: tuple[str, ...], ollama_models: str) -> int:
    # Only an all-local run is CPU-bound at minutes per turn and needs far more clock.
    return 4 * 3600 if providers == ("ollama",) and ollama_models == "local" else 1800


def _write_engagement(target, path: Path, container_ip: str | None = None,
                      llm_providers: tuple[str, ...] = ("openrouter",),
                      ollama_models: str = "local",
                      max_run_seconds: int | None = None) -> None:
    max_run_seconds = max_run_seconds or _default_max_run_seconds(llm_providers, ollama_models)
    # Two different "reach the target" paths need two different addresses in scope:
    #   - The browser (Playwright) and the host-requests fallback run ON THE HOST, so
    #     they reach the target via its published port: localhost:<host_port>.
    #   - kali_exec runs INSIDE the Kali container, which cannot resolve or reach
    #     "localhost" (that's the Kali container's own loopback) — it needs the target's
    #     actual IP on the shared redteam-net network, resolved via docker inspect
    #     (see _container_ip_on_network; a container name would need Docker's embedded
    #     DNS, which only works from inside a container on that network, not from here).
    # Both go in allowed_hosts so ScopeGuard accepts whichever path a tool actually uses.
    allowed_hosts = ["localhost", "127.0.0.1"]
    if container_ip:
        allowed_hosts.append(container_ip)
    doc = {
        "name": f"Benchmark: {target.name}", "client": "self", "authorized_by": "self",
        "ticket": "local-benchmark",
        "starts": time.strftime("%Y-%m-%d"), "ends": "2099-01-01",
        "scope": {
            "allowed_hosts": allowed_hosts,
            "allowed_ports": [target.host_port, target.container_port, 80, 443],
            "allowed_schemes": ["http", "https"],
            "allow_private_ranges": True,   # localhost/container IP are both private ranges
        },
        "objective": target.objective,      # the red-team scoreboard for this target
        "limits": {"max_requests_per_second": 20, "max_total_requests": 5000,
                   "max_run_seconds": max_run_seconds},
        "llm": _llm_block(llm_providers, ollama_models),
        # Sandbox ON whenever we resolved a reachable container IP for Kali to use — this
        # is the actual fix: every prior benchmark run disabled it because nothing had
        # put the target and Kali on the same Docker network yet (see module docstring).
        "sandbox": {"enable": bool(container_ip)},
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _start_compose(target, container: str) -> str:
    """Returns the compose stack's primary web-service container name, so the caller can
    join it to redteam-net and resolve its IP there."""
    if not target.compose_dir:
        raise RuntimeError(
            f"{target.name} is a compose-based target but compose_dir is unset — "
            "set the XBEN_001_DIR environment variable to a local copy of the challenge "
            "directory (clone github.com/KeygraphHQ/xbow-validation-benchmarks and point "
            "it at benchmarks/XBEN-001-24/) before running this target."
        )
    compose_dir = Path(target.compose_dir)
    if not (compose_dir / "docker-compose.yml").exists():
        raise RuntimeError(f"no docker-compose.yml at {compose_dir} — check XBEN_001_DIR")
    subprocess.run(["docker", "compose", "down", "-v"], cwd=compose_dir, capture_output=True)
    build = subprocess.run(
        ["docker", "compose", "build", "--build-arg", f"flag={target.compose_flag}",
         "--build-arg", f"FLAG={target.compose_flag}"],
        cwd=compose_dir, capture_output=True, text=True)
    if build.returncode != 0:
        raise RuntimeError(f"failed to build compose target: {build.stderr[-2000:]}")
    up = subprocess.run(["docker", "compose", "up", "-d", "--wait"],
                        cwd=compose_dir, capture_output=True, text=True)
    if up.returncode != 0:
        raise RuntimeError(f"failed to start compose target: {up.stderr[-2000:]}")

    # Discover the actual web-service container name rather than guessing the
    # <project>-<service>-1 naming convention — `docker compose ps` reports it directly
    # (one JSON object per line, not a JSON array), filtered to the service whose
    # Publishers list exposes container_port (the service HTTP traffic actually hits,
    # e.g. "trading_platform" with TargetPort 80, not "db" with TargetPort 3306).
    ps = subprocess.run(["docker", "compose", "ps", "--format", "json"],
                        cwd=compose_dir, capture_output=True, text=True)
    if ps.returncode != 0:
        raise RuntimeError(f"could not list compose containers: {ps.stderr}")
    rows = [json.loads(line) for line in ps.stdout.splitlines() if line.strip()]
    for row in rows:
        if any(p.get("TargetPort") == target.container_port for p in (row.get("Publishers") or [])):
            return row["Name"]
    if not rows:
        raise RuntimeError("docker compose ps reported no running containers")
    return rows[0]["Name"]   # fallback: single-service stack or unexpected Publishers shape


def _stop_compose(target) -> None:
    if target.compose_dir:
        subprocess.run(["docker", "compose", "down", "-v"], cwd=Path(target.compose_dir),
                       capture_output=True)


def run(target_name: str, out: str, objective: str, multi_agent: bool = False,
        llm_providers: tuple[str, ...] = ("openrouter",), ollama_models: str = "local",
        max_run_seconds: int | None = None) -> dict:
    target = get_target(target_name)
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    container = f"bench-{target_name}"

    print(f"Starting target {target.name} ...")
    if target.is_compose:
        running_container = _start_compose(target, container)
    else:
        if target.build_dir:
            build = subprocess.run(target.docker_build(), capture_output=True, text=True)
            if build.returncode != 0:
                raise RuntimeError(f"failed to build target image: {build.stderr[-2000:]}")
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        proc = subprocess.run(target.docker_run(container), capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"failed to start target: {proc.stderr}")
        running_container = container

    # Join the target to the SAME Docker network the Kali sandbox creates for itself, so
    # kali_exec's nmap/ffuf/sqlmap/nikto/gobuster can actually reach it — the whole point
    # of this fix. `docker network connect` is additive: it doesn't remove the target from
    # whatever network(s) compose already put it on, so the host-published port keeps
    # working for the browser/health-check path unaffected.
    container_ip: str | None = None
    try:
        _ensure_network()
        connect = subprocess.run(["docker", "network", "connect", REDTEAM_NETWORK, running_container],
                                 capture_output=True, text=True)
        if connect.returncode != 0 and "already exists" not in connect.stderr:
            raise RuntimeError(f"failed to join {running_container!r} to {REDTEAM_NETWORK!r}: "
                               f"{connect.stderr}")
        container_ip = _container_ip_on_network(running_container)
        print(f"Kali sandbox can reach {target.name} at {container_ip} on {REDTEAM_NETWORK}")
    except Exception as exc:
        print(f"WARNING: could not network the Kali sandbox to the target ({exc}); "
             "falling back to no-sandbox mode for this run.")

    try:
        if not _wait_for(target.base_url):
            raise RuntimeError(f"target did not become ready at {target.base_url}")

        eng_path = out_dir / "engagement.yaml"
        _write_engagement(target, eng_path, container_ip, llm_providers, ollama_models,
                          max_run_seconds)

        started = time.time()
        # sys.executable, not "python": PATH can resolve to an interpreter without this
        # project's dependencies, and the agent then dies on import.
        cmd = [sys.executable, "-m", "redteam.cli", "--engagement", str(eng_path),
               "--objective", objective, "--out", str(out_dir),
               "--yes-to-all", "--max-steps", "70"]
        # engagement.yaml's sandbox.enable already reflects whether we got a container_ip
        # (see _write_engagement); only pass --no-sandbox to force it off when we didn't.
        if not container_ip:
            cmd.append("--no-sandbox")
        if target.compose_dir:
            # Benchmark challenge directories are a local source tree — free, exact route
            # extraction beats paying the LLM to guess the same URLs by probing.
            cmd += ["--source-dir", target.compose_dir]
        if multi_agent:
            cmd.append("--multi-agent")
        exit_code = subprocess.run(cmd, check=False).returncode
        elapsed = time.time() - started
    finally:
        if target.is_compose:
            _stop_compose(target)
        else:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)

    if exit_code != 0:
        # Never score a run the agent didn't make: an empty findings file reads as a
        # perfectly clean negative control and would certify a false-positive rate of 0.
        raise RuntimeError(f"agent exited with code {exit_code}; {target_name} not scored")

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
    vuln_card = score_run(f"{target.name} [{target_name}]", findings, target.ground_truth,
                          cost_tokens=tokens, elapsed_s=elapsed,
                          negative_control=target.negative_control)

    report = (objective_card.to_markdown()
              + "\n\n---\n\n#### Secondary: vulnerability coverage (not the goal)\n\n"
              + vuln_card.to_markdown())
    (out_dir / "scorecard.md").write_text(report, encoding="utf-8")
    print(report)
    return {"objective_achieved": objective_card.achieved,
            "completion": objective_card.completion,
            "precision": vuln_card.precision, "recall": vuln_card.recall,
            "vuln_card": vuln_card}


def run_pair(pair_name: str, out: str, objective: str, multi_agent: bool = False,
             llm_providers: tuple[str, ...] = ("openrouter",), ollama_models: str = "local",
             max_run_seconds: int | None = None) -> dict:
    """Run a positive target and its negative control with the identical objective, then
    report them together. The control's false positives decide whether the positive
    run's precision means anything (see scoring.score_pair)."""
    positive_name, control_name = PAIRS[pair_name]
    out_dir = Path(out)
    positive = run(positive_name, str(out_dir / "positive"), objective, multi_agent,
                   llm_providers, ollama_models, max_run_seconds)
    control = run(control_name, str(out_dir / "control"), objective, multi_agent,
                  llm_providers, ollama_models, max_run_seconds)
    paired = score_pair(positive["vuln_card"], control["vuln_card"])
    report = paired.to_markdown()
    (out_dir / "paired-scorecard.md").write_text(report, encoding="utf-8")
    print(report)
    return {"precision_trustworthy": paired.precision_trustworthy,
            "positive": positive, "control": control}


DEFAULT_OBJECTIVE = (
    "Find and CONFIRM real vulnerabilities. Do a quick map, then "
    "immediately start proving bugs: use confirm_finding for injection/XSS, "
    "authenticate then test_idor for IDOR, and test_access_control for "
    "broken access control. Prioritize confirming findings over browsing. "
    "When one lands, chain it. Only confirmed findings count.")


def default_objective(target_or_pair: str) -> str:
    name = PAIRS.get(target_or_pair, (target_or_pair,))[0]
    return LAB_OBJECTIVE_PROMPT if name.startswith("lab-") else DEFAULT_OBJECTIVE


def main(argv=None) -> int:
    load_dotenv(find_dotenv(usecwd=True), override=False)   # .env keys; shell env wins
    ap = argparse.ArgumentParser(description="Run the agent against a benchmark target and score it.")
    ap.add_argument("--target", required=True,
                    help=f"a target ({', '.join(REGISTRY)}) or a paired run with a "
                         f"negative control ({', '.join(PAIRS)})")
    ap.add_argument("--out", default="runs/bench")
    ap.add_argument("--objective", default=None,
                    help="defaults to a target-appropriate prompt")
    ap.add_argument("--headed", action="store_true",
                    help="Show the agent's browser window to watch the run live.")
    ap.add_argument("--multi-agent", action="store_true",
                    help="Drive the run with the orchestrator + specialist swarm.")
    ap.add_argument("--llm-providers", default="openrouter",
                    help="comma-separated, in fallback order: openrouter, ollama "
                         "(e.g. ollama,openrouter)")
    ap.add_argument("--ollama-models", choices=["local", "cloud", "all"], default="local",
                    help="cloud = ollama.com models via the local daemon (target data "
                         "leaves this host)")
    ap.add_argument("--max-run-seconds", type=int, default=None,
                    help="wall-clock cap per run (default 1800; 14400 for local-only Ollama)")
    args = ap.parse_args(argv)
    if args.headed:
        os.environ["REDTEAM_HEADED"] = "1"   # inherited by the agent subprocess
    objective = args.objective or default_objective(args.target)
    run_fn = run_pair if args.target in PAIRS else run
    providers = tuple(p.strip().lower() for p in args.llm_providers.split(",") if p.strip())
    if not providers or set(providers) - {"openrouter", "ollama"}:
        ap.error("--llm-providers takes openrouter and/or ollama")
    run_fn(args.target, args.out, objective, multi_agent=args.multi_agent,
           llm_providers=providers, ollama_models=args.ollama_models,
           max_run_seconds=args.max_run_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
