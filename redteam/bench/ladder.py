"""The frontier-standoff matrix: {raw, rawk, flat, swarm} x {backend, model} on one
target set, one scorer, one table.

WHY (the question this answers): "how much does our tool stand against frontier
models" is not one number. It is two axes:

  MODE isolates scaffolding, holding the model fixed:
    raw    — one blind shot: the model names requests, we replay them, its cited
             evidence is checked mechanically. No loop, no memory, no tools.
    rawk   — K feedback rounds (default 3). The loop is the ONLY addition over raw.
    flat   — the full single agent: tools, memory, guardrails, verify protocol.
    swarm  — orchestrator + OWASP class specialists (the flagship).

  BACKEND isolates the model, holding the mode fixed:
    zai-bridge / zai-direct / anthropic / openrouter / openai / custom — all through
    the same engagement `llm.providers` plumbing, so provider behavior (rotation,
    role routing, cooldowns) is identical across arms.

Reading the table:
  rawk - raw  = value of feedback alone
  flat - rawk = value of the tool loop + protocol
  swarm - flat = value of specialists + claim discipline
  and each column again on a frontier backend = what the model tier buys per rung.

Cells run ONE per invocation (sandbox reaps processes between tool calls; a whole
matrix cannot survive a single shell). Chunk with --cells:

    python -m redteam.bench.ladder --targets lab-idor,ladder-3 --modes raw,rawk \
        --backend zai-bridge --out runs/frontier-standoff --cells 0-1

Merging is separate and cheap: --merge-only rebuilds frontier-matrix.md from the
per-cell card files whenever called.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from .targets import REGISTRY, get_target

MODES = ("raw", "rawk", "flat", "swarm")
RAW_ROUNDS = {"raw": 1, "rawk": 3}

# -- Backend presets ------------------------------------------------------------------
# All arms share the gateway's rotation/cooldown semantics; a preset only decides
# which fleet the engagement points at. Tool support: the bridge/direct z-ai fleet
# lacks the OpenRouter discovery endpoint, so discovery is allowlist-driven
# (require_tool_support False = don't demand /models tool-capability metadata).

def _backend_preset(name: str, model: str) -> dict:
    presets = {
        "zai-bridge": dict(kind="openai_compat", name="zai-sdk",
                           base_url="http://127.0.0.1:9825/v1",
                           api_key_env="ZAI_BRIDGE_KEY",
                           models=["glm-4.6"], prefer_free=False,
                           require_tool_support=False, priority=10),
        "zai-direct": dict(kind="zai", name="zai", api_key_env="ZAI_API_KEY",
                           models=["glm-4.6"], prefer_free=False,
                           require_tool_support=False, priority=10),
        "anthropic": dict(kind="anthropic", name="anthropic",
                          api_key_env="ANTHROPIC_API_KEY",
                          models=["claude-sonnet-4-5"], prefer_free=False,
                          require_tool_support=False, priority=10),
        "openrouter": dict(kind="openrouter", name="openrouter",
                           api_key_env="OPENROUTER_API_KEY",
                           models=[], prefer_free=False,
                           require_tool_support=False, priority=10),
        "openai": dict(kind="openai", name="openai", api_key_env="OPENAI_API_KEY",
                       models=[], prefer_free=False,
                       require_tool_support=False, priority=10),
    }
    if name == "custom":
        base = os.environ.get("RED_LADDER_BASE_URL", "")
        if not base:
            raise SystemExit("backend 'custom' needs RED_LADDER_BASE_URL")
        presets["custom"] = dict(kind="openai_compat", name="custom",
                                 base_url=base,
                                 api_key_env=os.environ.get("RED_LADDER_KEY_ENV",
                                                            "RED_LADDER_API_KEY"),
                                 models=[], prefer_free=False,
                                 require_tool_support=False, priority=10)
    if name not in presets:
        raise SystemExit(
            f"unknown backend {name!r}; known: {sorted(set(presets) | {'custom'})}")
    preset = dict(presets[name])
    if model:
        preset["models"] = [model] if ":" not in model or name in (
            "openrouter", "openai", "custom") else [model.split(":", 1)[1]]
    if not preset["models"]:
        raise SystemExit(f"backend {name!r} needs --model (e.g. --model gpt-5.1)")
    return preset


# -- Engagement + objective seeding ------------------------------------------------------

def write_engagement(target, path: Path, backend_preset: dict) -> None:
    """Same RoE shape the bench runner writes; the llm block is the only variable."""
    doc = {
        "name": f"Bench: {target.name}",
        "client": "Internal", "authorized_by": "Operator (this machine)",
        "ticket": "FRONTIER-STANDOFF",
        "starts": "2026-10-01", "ends": "2026-12-31",
        "scope": {
            "allowed_hosts": ["127.0.0.1"],
            "excluded_hosts": [],
            "allowed_ports": [target.host_port],
            "allowed_schemes": ["http"],
            "allow_private_ranges": True,
        },
        "limits": {"max_requests_per_second": 5, "max_total_requests": 700,
                   "max_run_seconds": 600, "max_llm_tokens": 800000},
        "llm": {
            "temperature": 0.2, "max_tokens": 4096,
            "providers": [{k: v for k, v in backend_preset.items() if v != ""}],
        },
        "sandbox": {"enable": False},
    }
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def canonical_objective_text(target) -> str:
    """One objective text for every arm — the briefing a red team lead would hand a
    contractor, identical for the swarm and for the raw model."""
    obj = target.objective
    lines = [f"{obj['name']}. {obj['description']}", "Success criteria:"]
    for c in obj["success_criteria"]:
        lines.append(f"- [{c['id']}] {c['description']}")
    return "\n".join(lines)


# -- Cell runner -----------------------------------------------------------------------

def plan_cells(targets: list[str], modes: list[str]) -> list[tuple[str, str]]:
    """Mode-major within target: a chunk that dies mid-run still leaves one complete
    mode row for the target it was covering."""
    return [(t, m) for t in targets for m in modes]


def start_target(target, out_dir: Path):
    """Dockerless lab targets only — this matrix runs where Docker doesn't."""
    if not target.is_cmd:
        raise SystemExit(
            f"target {target.name!r} is Docker-backed; the frontier-standoff matrix "
            "runs the dockerless lab targets (lab-idor, lab-forum, ladder-1..3). "
            "Use redteam.bench.runner for the Docker suite.")
    log = (out_dir / "target.log").open("w")
    proc = subprocess.Popen(target.cmd, env={**os.environ, **target.env},
                            stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 30
    import urllib.request
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(target.base_url, timeout=3) as r:
                if r.status < 500:
                    return proc, log
        except Exception:
            time.sleep(0.5)
    proc.terminate()
    log.close()
    raise SystemExit(f"target {target.name} did not come up at {target.base_url}")


def run_cell(target_key: str, mode: str, backend: str, out_root: Path,
             model: str = "", max_steps: int = 70) -> dict:
    """One matrix cell: target x mode x backend. Returns the card dict."""
    target = get_target(target_key)
    preset = _backend_preset(backend, model)
    model = model or preset["models"][0]
    cell_dir = out_root / f"{target_key}--{mode}--{backend}"
    cell_dir.mkdir(parents=True, exist_ok=True)

    eng_path = cell_dir / "engagement.yaml"
    write_engagement(target, eng_path, preset)
    (cell_dir / "objective.json").write_text(json.dumps({
        "name": target.objective["name"],
        "description": target.objective["description"],
        "criteria": [dict(c, achieved=False, achieved_at="")
                     for c in target.objective["success_criteria"]],
    }, indent=1), encoding="utf-8")
    objective_text = canonical_objective_text(target)

    proc, log = start_target(target, cell_dir)
    started = time.time()
    try:
        if mode in ("flat", "swarm"):
            cmd = [sys.executable, "-m", "redteam.cli", "--engagement", str(eng_path),
                   "--objective", objective_text, "--out", str(cell_dir),
                   "--yes-to-all", "--max-steps", str(max_steps)]
            if mode == "swarm":
                cmd.append("--multi-agent")
            subprocess.run(cmd, check=False)
        elif mode in ("raw", "rawk"):
            cmd = [sys.executable, "-m", "redteam.bench.raw_baseline",
                   "--engagement", str(eng_path), "--objective", objective_text,
                   "--out", str(cell_dir),
                   "--rounds", str(RAW_ROUNDS[mode]),
                   "--model", f"{preset['name']}:{preset['models'][0]}"]
            subprocess.run(cmd, check=False)
        else:
            raise SystemExit(f"unknown mode {mode!r}; known: {MODES}")
    finally:
        elapsed = time.time() - started
        proc.terminate()
        log.close()

    card = score_cell(cell_dir, target_key, mode, backend,
                      preset["models"][0], elapsed)
    (cell_dir / "cell.card.json").write_text(json.dumps(card, indent=1),
                                             encoding="utf-8")
    return card


def score_cell(cell_dir: Path, target_key: str, mode: str, backend: str,
               model: str, elapsed: float) -> dict:
    """Score with the same machinery the bench runner uses — objective primary,
    confirmed-findings F1 secondary. Both arms read identical artifacts."""
    from ..access import AccessGraph
    from ..objective import Objective
    from .objective_scoring import score_objective_run

    objective = Objective.load(cell_dir / "objective.json")
    access = (AccessGraph(cell_dir / "access.json")
              if (cell_dir / "access.json").exists() else None)

    findings_path = cell_dir / "findings.json"
    findings = (json.loads(findings_path.read_text(encoding="utf-8"))
                if findings_path.exists() else [])
    tokens = actions = steps = 0
    manifest_path = cell_dir / "manifest.json"
    halt_reason = ""
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        tokens = int(manifest.get("tokens") or 0)
        steps = int(manifest.get("steps") or 0)
        halt_reason = str(manifest.get("halt_reason") or "")
    audit_path = cell_dir / "audit.log.jsonl"
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            try:
                ev = json.loads(line).get("event", "")
            except json.JSONDecodeError:
                continue
            if ev == "agent.turn":
                steps += 1
            if ev.startswith(("http_request", "browser.", "sandbox.exec",
                              "template.apply", "verify_vuln", "confirm.")):
                actions += 1
    confirmed = len([f for f in findings
                     if f.get("confidence") == "confirmed"
                     and f.get("severity") != "info"])

    target = get_target(target_key)
    obj_card = score_objective_run(target.name, objective, access, steps=steps,
                                   elapsed_s=elapsed, tokens=tokens,
                                   actions=actions, confirmed_findings=confirmed)
    from .scoring import score_run
    vuln_card = score_run(target.name, findings, target.ground_truth,
                          cost_tokens=tokens, elapsed_s=elapsed)
    return {
        "target_key": target_key, "target": target.name,
        "mode": mode, "backend": backend, "model": model,
        "objective_achieved": obj_card.achieved,
        "completion": obj_card.completion,
        "confirmed": confirmed,
        "precision": vuln_card.precision, "recall": vuln_card.recall,
        "f1": vuln_card.f1,
        "steps": steps, "actions": actions, "tokens": tokens,
        "elapsed_s": round(elapsed, 1),
        "halt_reason": halt_reason,
    }


# -- Merge -------------------------------------------------------------------------------

def merge(out_root: Path) -> str:
    """Rebuild frontier-matrix.md from every cell card under out_root."""
    cards = []
    for card_path in sorted(out_root.glob("*--*--*/cell.card.json")):
        try:
            cards.append(json.loads(card_path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            continue
    lines = ["# Frontier-standoff matrix", "",
             "One target set, one scorer. Mode isolates scaffolding; backend isolates "
             "the model.", ""]
    if not cards:
        lines.append("(no cells scored yet)")
        text = "\n".join(lines)
        (out_root / "frontier-matrix.md").write_text(text, encoding="utf-8")
        return text

    lines += [
        "| target | mode | backend | model | achieved | completion | confirmed | F1 | tokens | halt |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in sorted(cards, key=lambda x: (x["target_key"], MODES.index(x["mode"]),
                                          x["backend"])):
        lines.append(
            f"| {c['target_key']} | {c['mode']} | {c['backend']} | {c['model']} "
            f"| {'YES' if c['objective_achieved'] else 'no'} | {c['completion']} "
            f"| {c['confirmed']} | {c['f1']} | {c['tokens']} "
            f"| {(c['halt_reason'] or '')[:40]} |")

    # Mode aggregates per backend: the scaffolding deltas, averaged over targets.
    lines += ["", "## Scaffolding deltas (mean over targets, per backend)", "",
              "| backend | mode | achieved % | mean completion | mean F1 | mean tokens |",
              "| --- | --- | --- | --- | --- | --- |"]
    by_backend: dict[str, dict[str, list[dict]]] = {}
    for c in cards:
        by_backend.setdefault(c["backend"], {}).setdefault(c["mode"], []).append(c)
    for backend, modes in sorted(by_backend.items()):
        for mode in MODES:
            group = modes.get(mode)
            if not group:
                continue
            n = len(group)
            lines.append(
                f"| {backend} | {mode} "
                f"| {sum(1 for c in group if c['objective_achieved']) * 100 // n}% "
                f"| {sum(c['completion'] for c in group) / n:.2f} "
                f"| {sum(c['f1'] for c in group) / n:.2f} "
                f"| {sum(c['tokens'] for c in group) // n} |")
    text = "\n".join(lines) + "\n"
    (out_root / "frontier-matrix.md").write_text(text, encoding="utf-8")
    return text


# -- CLI -----------------------------------------------------------------------------

def _parse_cells(spec: str, total: int) -> list[int]:
    if not spec:
        return list(range(total))
    out: set[int] = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo), int(hi) + 1))
        else:
            out.add(int(part))
    bad = [i for i in out if i < 0 or i >= total]
    if bad:
        raise SystemExit(f"cell indices {bad} out of range (0..{total - 1})")
    return sorted(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Frontier-standoff matrix runner")
    ap.add_argument("--targets", default="lab-idor,ladder-1,ladder-2,ladder-3")
    ap.add_argument("--modes", default="swarm",
                    help="comma list from: raw,rawk,flat,swarm")
    ap.add_argument("--backend", default="zai-bridge")
    ap.add_argument("--model", default="", help="override the backend's model id")
    ap.add_argument("--out", default="runs/frontier-standoff")
    ap.add_argument("--cells", default="",
                    help="subset of the planned cells to run this invocation, "
                         "e.g. '0-1' or '3' (one per shell call in this sandbox)")
    ap.add_argument("--max-steps", type=int, default=70)
    ap.add_argument("--merge-only", action="store_true",
                    help="rebuild frontier-matrix.md from existing cards and exit")
    args = ap.parse_args(argv)

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    if args.merge_only:
        print(merge(out_root))
        return 0

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    for t in targets:
        if t not in REGISTRY:
            raise SystemExit(f"unknown target {t!r}; known: {sorted(REGISTRY)}")
    for m in modes:
        if m not in MODES:
            raise SystemExit(f"unknown mode {m!r}; known: {MODES}")

    # Plan order: mode-major within target so a chunk of cells covers all modes of
    # one target — a killed run still leaves a complete mode row to read.
    plan = plan_cells(targets, modes)
    cells = _parse_cells(args.cells, len(plan))
    for idx in cells:
        t, m = plan[idx]
        print(f"=== cell {idx}: {t} x {m} x {args.backend} ===", flush=True)
        card = run_cell(t, m, args.backend, out_root, model=args.model,
                        max_steps=args.max_steps)
        print(json.dumps({k: card[k] for k in
                          ("target_key", "mode", "objective_achieved", "completion",
                           "confirmed", "f1", "tokens")}, indent=1), flush=True)
    print(merge(out_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
