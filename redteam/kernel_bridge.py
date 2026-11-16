"""llmred-kernel bridge — Rust compute, Python contract.

The kernel (kernel/ in the repo root, `cargo build --release`) runs three
engines behind a JSON-over-stdio protocol:

  scan_canaries      evidence/traffic processing: one Aho-Corasick pass
                     finds every canary encoding variant in a transcript
  plan_attack_graph  dynamic attack-graph planner: layering, transitive
                     dead-state detection, next-frontier selection
  optimize_coverage  greedy max-coverage under budget

Design rules (pressure-tested):

1. The kernel computes spans, indices and plans. It NEVER emits a verdict —
   the three-verdict contract (SUCCEEDED / RESISTED / INCONCLUSIVE) stays in
   the auditable Python oracle layer, and a kernel bug cannot fabricate a
   RESISTED or a SUCCEEDED.
2. Every kernel op has a Python reference implementation here with IDENTICAL
   output (same values, same order). Tests run kernel-vs-reference equality
   on random inputs; CI without a Rust toolchain still passes on the
   reference. The kernel is an accelerator and a hardening boundary, never a
   second source of truth.
3. A present-but-broken kernel raises: contract bugs must surface, never be
   silently masked by a fallback.
4. Protocol: the bridge keeps ONE persistent kernel process per interpreter
   (JSONL request/response, flushed per line). Jobs larger than the pipe
   buffer go through a one-shot `communicate()` call instead — both paths
   speak the same line protocol.
5. Positional parity: the kernel reports CHARACTER offsets into the
   lowercased haystack (Python `str.find` semantics), verified against
   multi-byte text.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

__all__ = [
    "kernel_available",
    "kernel_version",
    "call_kernel",
    "close_kernel",
    "scan_canaries",
    "plan_attack_graph",
    "optimize_coverage",
]

# Jobs serialized larger than this go one-shot (pipe-buffer deadlock guard).
_PERSISTENT_MAX_BYTES = 24_000
_KERNEL_ENV = "LLMRED_KERNEL_BIN"
_DISABLE_ENV = "LLMRED_KERNEL"

_state: dict[str, Any] = {"proc": None, "bin": None, "checked": False}


def _locate_binary() -> str | None:
    if os.environ.get(_DISABLE_ENV, "").strip().lower() in {"off", "false", "0", "no"}:
        return None
    candidates: list[str] = []
    env_bin = os.environ.get(_KERNEL_ENV)
    if env_bin:
        candidates.append(env_bin)
    repo_bin = (
        Path(__file__).resolve().parent.parent / "kernel" / "target"
        / "release" / "llmred-kernel"
    )
    candidates.append(str(repo_bin))
    on_path = shutil.which("llmred-kernel")
    if on_path:
        candidates.append(on_path)
    for cand in candidates:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def kernel_available() -> bool:
    """True when a compiled kernel binary exists and is executable."""
    if not _state["checked"]:
        _state["checked"] = True
        _state["bin"] = _locate_binary()
    return _state["bin"] is not None


def kernel_version() -> str | None:
    """Kernel binary version string, or None when unavailable."""
    if not kernel_available():
        return None
    try:
        out = call_kernel(
            {"op": "scan_canaries", "params": {"text": "", "canaries": []}}
        )
    except RuntimeError:
        return None
    return out.get("kernel_version")


def close_kernel() -> None:
    """Terminate the persistent kernel process (idempotent)."""
    proc = _state.get("proc")
    if proc is not None:
        try:
            proc.stdin.close()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    _state["proc"] = None


atexit.register(close_kernel)


def call_kernel(job: dict) -> dict:
    """One JSON job -> one JSON result. Raises RuntimeError on any failure —
    a present-but-broken kernel is a contract bug, never masked."""
    if not kernel_available():
        raise RuntimeError("llmred-kernel binary unavailable")
    payload = json.dumps(job, ensure_ascii=False).encode("utf-8")
    proc = _state.get("proc")
    if proc is None or proc.poll() is not None:
        proc = subprocess.Popen(
            [_state["bin"]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _state["proc"] = proc
    try:
        if len(payload) <= _PERSISTENT_MAX_BYTES:
            assert proc.stdin is not None and proc.stdout is not None
            proc.stdin.write(payload + b"\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("kernel closed the pipe unexpectedly")
        else:
            out, err = proc.communicate(payload + b"\n", timeout=120)
            _state["proc"] = None
            if proc.returncode != 0:
                raise RuntimeError(
                    "kernel exit %s: %s" % (proc.returncode, err.decode(errors="replace")[:300])
                )
            lines = [ln for ln in out.decode("utf-8", errors="replace").splitlines() if ln.strip()]
            if not lines:
                raise RuntimeError("kernel produced no output")
            line = lines[-1]
    except RuntimeError:
        raise
    except Exception as exc:  # broken pipe etc. — surface, never mask
        close_kernel()
        raise RuntimeError(f"kernel transport failed: {exc}") from exc
    result = json.loads(line)
    if "error" in result:
        raise RuntimeError(f"kernel error: {result['error']}")
    return result


# ---------------------------------------------------------------- scan ------

def scan_canaries(text: str, canaries: list[str]) -> list[dict]:
    """Every (canary_index, variant, pos, len) hit of the canaries' encoding
    variants in text — grouped by canary then variant in canonical order,
    positions ascending. Kernel pass when available; otherwise the
    byte-identical Python reference (the same loop oracles.canary_hits has
    always run)."""
    if not canaries or not text:
        return []
    if kernel_available():
        out = call_kernel(
            {"op": "scan_canaries", "params": {"text": text, "canaries": canaries}}
        )
        return out["result"]["hits"]
    return _scan_canaries_py(text, canaries)


def _scan_canaries_py(text: str, canaries: list[str]) -> list[dict]:
    from .pi.oracles import _canary_variants  # lazy: avoids import cycle

    hits: list[dict] = []
    low = text.lower()
    for ci, canary in enumerate(canaries):
        if not canary:
            continue
        for name, needle in _canary_variants(canary):
            nl = needle.lower()
            start = 0
            while True:
                idx = low.find(nl, start)
                if idx < 0:
                    break
                hits.append(
                    {"canary_index": ci, "variant": name, "pos": idx, "len": len(nl)}
                )
                start = idx + 1
    return hits


# --------------------------------------------------------------- graph ------

def plan_attack_graph(
    nodes: list[dict], achieved: list[str], budget: int | None = None
) -> dict:
    """Layered attack plan. nodes: [{id, score, requires[]}]; achieved:
    capability labels + already-evidenced node ids. Returns {levels,
    ready_now, dead, dead_reasons, stalled}."""
    if kernel_available():
        out = call_kernel(
            {
                "op": "plan_attack_graph",
                "params": {"nodes": nodes, "achieved": achieved, "budget": budget},
            }
        )
        return out["result"]
    return _plan_attack_graph_py(nodes, achieved, budget)


def _plan_attack_graph_py(
    nodes: list[dict], achieved: list[str], budget: int | None = None
) -> dict:
    ids = {n["id"] for n in nodes}
    achieved_set = set(achieved)
    cap = budget if budget is not None else len(nodes)

    def blocking(n: dict) -> str | None:
        for r in n.get("requires", []):
            known = r in ids or r in achieved_set
            if not known or r in dead:
                return r
        return None

    dead: set[str] = set()
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n["id"] in dead:
                continue
            if blocking(n) is not None:
                dead.add(n["id"])
                changed = True
    dead_reasons = {n["id"]: blocking(n) for n in nodes if n["id"] in dead}

    alive = [n for n in nodes if n["id"] not in dead and n["id"] not in achieved_set]
    indeg = {
        n["id"]: sum(
            1
            for r in n.get("requires", [])
            if r not in achieved_set and r in ids and r not in dead
        )
        for n in alive
    }
    dependents: dict[str, list[str]] = {}
    for n in alive:
        for r in n.get("requires", []):
            if r not in achieved_set and r in ids and r not in dead:
                dependents.setdefault(r, []).append(n["id"])

    def by_score_desc_id_asc(items: list[str]) -> list[str]:
        score = {n["id"]: n.get("score", 0.0) for n in nodes}
        return sorted(items, key=lambda i: (-score.get(i, 0.0), i))

    frontier = by_score_desc_id_asc([i for i, d in indeg.items() if d == 0])
    levels: list[list[str]] = []
    leveled: set[str] = set()
    while frontier:
        levels.append(list(frontier))
        leveled.update(frontier)
        nxt: list[str] = []
        for fid in frontier:
            for dep in dependents.get(fid, []):
                indeg[dep] -= 1
                if indeg[dep] == 0:
                    nxt.append(dep)
        frontier = by_score_desc_id_asc(nxt)

    ready_now = by_score_desc_id_asc(
        [
            n["id"]
            for n in alive
            if all(r in achieved_set for r in n.get("requires", []))
        ][:cap]
    )
    stalled = sorted(n["id"] for n in alive if n["id"] not in leveled)
    return {
        "levels": levels,
        "ready_now": ready_now,
        "dead": sorted(dead),
        "dead_reasons": [
            {"node": d, "missing": dead_reasons.get(d, "")} for d in sorted(dead)
        ],
        "stalled": stalled,
    }


# ----------------------------------------------------------- coverage -------

def optimize_coverage(items: list[dict], budget: int) -> dict:
    """Greedy max-coverage under budget. items: [{id, score, covers[]}].
    Deterministic tie-break: new labels desc, score desc, id asc; `selected`
    is in pick order."""
    if kernel_available():
        out = call_kernel(
            {
                "op": "optimize_coverage",
                "params": {"items": items, "budget": budget},
            }
        )
        return out["result"]
    return _optimize_coverage_py(items, budget)


def _optimize_coverage_py(items: list[dict], budget: int) -> dict:
    covered: set[str] = set()
    chosen: list[str] = []
    selected: set[str] = set()
    for _ in range(budget):
        best: dict | None = None
        best_new = 0
        for it in items:
            if it["id"] in selected:
                continue
            new = sum(1 for lbl in it.get("covers", []) if lbl not in covered)
            if new == 0:
                continue
            take = best is None or (
                new > best_new
                or (
                    new == best_new
                    and (
                        it.get("score", 0.0) > best.get("score", 0.0)
                        or (
                            it.get("score", 0.0) == best.get("score", 0.0)
                            and it["id"] < best["id"]
                        )
                    )
                )
            )
            if take:
                best, best_new = it, new
        if best is None:
            break
        covered.update(best.get("covers", []))
        selected.add(best["id"])
        chosen.append(best["id"])
    all_labels = sorted({lbl for it in items for lbl in it.get("covers", [])})
    return {
        "selected": chosen,
        "covered_labels": sorted(covered),
        "uncovered": [lbl for lbl in all_labels if lbl not in covered],
    }
