"""build_coverage — the asset coverage map (ARTEX 资产覆盖图) from run artifacts.

ARTEX's dashboard answers the operator's second most important question with a
picture: of everything the RoE ALLOWS us to touch, what did we actually test?
A finding list says what we found; it is silent about everything we never
tried. An honest coverage map is the antidote to the "agent worked hard"
illusion — it names the untouched ground in plain terms.

This module is a pure adapter over the per-run artifact files (same discipline
as graph_view: the server stays decoupled from the engine):

    scope.json         the frozen RoE grid (hosts x ports) — written at run start
    attack_tree.json   planned/attempted branches and their status
    findings.json      recorded findings + verification state
    inventory.json     services seen per host (passive fingerprints)

The universe is the RoE grid, never the activity: a host:port pair the agent
invented does not become "covered" by being attacked, and activity outside the
grid is reported separately as a scope anomaly for the operator to see, not
silently folded in. Coverage states, per pair:

    tested          a technique on this pair reached COMPLETED, or a finding
                    targets it — proof landed here
    attempted       techniques were tried (in progress / failed) but nothing proved
    alive_untouched inventory saw a live service here; nobody has tried anything
    untouched       in scope, nothing seen, nothing tried

Missing artifacts degrade honestly (no scope.json -> no grid -> coverage is
reported from activity alone with the limitation named).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

TESTED, ATTEMPTED, ALIVE_UNTOUCHED, UNTOUCHED = (
    "tested", "attempted", "alive_untouched", "untouched")

# attack-tree statuses that count as "someone actually worked this pair"
_ATTEMPT_STATUSES = {"in_progress", "failed", "completed", "confirmed"}
_DONE_STATUSES = {"completed", "confirmed"}


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _host_port_of(target: str) -> tuple[str, int | None]:
    """Best-effort (host, port) from a tree/finding target: URL, host:port, or bare
    host. Returns ("", None) for anything unparseable — never guesses a hostname."""
    t = str(target or "").strip()
    if not t:
        return "", None
    if "://" not in t:
        t = "//" + t
    parsed = urlparse(t)
    host = (parsed.hostname or "").lower()
    if not host:
        return "", None
    port = parsed.port
    if port is None and parsed.scheme == "https":
        port = 443
    elif port is None and parsed.scheme == "http":
        port = 80
    return host, port


def build_coverage(run_dir: str | Path) -> dict:
    rd = Path(run_dir)
    scope = _read_json(rd / "scope.json", None)
    tree = _read_json(rd / "attack_tree.json", []) or []
    findings = _read_json(rd / "findings.json", []) or []
    inv = _read_json(rd / "inventory.json", {}) or {}

    # --- what the agent DID, keyed by (host, port-or-None) ---------------------
    attempted: dict[tuple[str, int | None], dict[str, int]] = {}
    proved: set[tuple[str, int | None]] = set()
    outside_scope: set[str] = set()

    for node in tree:
        host, port = _host_port_of(node.get("target", ""))
        if not host:
            continue
        key = (host, port)
        status = str(node.get("status", "")).lower()
        counts = attempted.setdefault(key, {})
        counts[status] = counts.get(status, 0) + 1
    for f in findings:
        host, port = _host_port_of(f.get("target", ""))
        if not host:
            continue
        proved.add((host, port))

    # --- the universe: the frozen RoE grid -------------------------------------
    grid: set[tuple[str, int]] = set()
    if scope:
        for host in scope.get("allowed_hosts", []):
            for port in scope.get("allowed_ports", []):
                grid.add((str(host).lower(), int(port)))

    # anything the agent touched that the grid does not contain = scope anomaly.
    # The scope guard should have blocked these; the report surfaces survivors
    # instead of hiding them (defense in depth — trust, then verify).
    def _in_grid(host: str, port: int | None) -> bool:
        if not grid:
            return True
        if port is None:
            return any(h == host for h, _ in grid)
        return (host, port) in grid or any(h == host and p is None for h, p in grid)

    for (host, port) in set(attempted) | proved:
        if grid and not _in_grid(host, port):
            outside_scope.add(f"{host}" + (f":{port}" if port is not None else ""))

    # --- alive services from passive inventory ---------------------------------
    alive: set[tuple[str, int]] = set()
    for host, rec in (inv.get("hosts") or {}).items():
        for svc in (rec or {}).get("services", {}).values():
            try:
                alive.add((str(host).lower(), int(svc.get("port", -1))))
            except (TypeError, ValueError):
                continue

    # --- fold into per-host coverage -------------------------------------------
    hosts_out: list[dict] = []
    totals = {TESTED: 0, ATTEMPTED: 0, ALIVE_UNTOUCHED: 0, UNTOUCHED: 0}
    interesting_hosts = ({h for h, _ in grid} | {h for h, _ in attempted}
                         | {h for h, _ in alive})
    for host in sorted(interesting_hosts):
        ports = sorted({p for h, p in grid if h == host}
                       | {p for h, p in attempted if h == host and p is not None}
                       | {p for h, p in alive if h == host})
        port_rows = []
        host_touched = False
        for port in ports:
            statuses = attempted.get((host, port)) or {}
            # a bare-host attempt (no port parseable) counts for every port row of
            # that host: the work demonstrably targeted this host.
            bare = attempted.get((host, None)) or {}
            merged: dict[str, int] = dict(bare)
            for s, n in statuses.items():
                merged[s] = merged.get(s, 0) + n
            has_finding = (host, port) in proved or (host, None) in proved
            tried_any = any(s in _ATTEMPT_STATUSES for s in merged) or bool(statuses)
            done_any = any(s in _DONE_STATUSES for s in merged)
            if has_finding or done_any:
                state = TESTED
            elif tried_any:
                state = ATTEMPTED
            elif (host, port) in alive:
                state = ALIVE_UNTOUCHED
            else:
                state = UNTOUCHED
            # totals are the IN-SCOPE accounting: an out-of-grid pair (e.g. a
            # live service on a port the RoE never allowed) shows in its host's
            # row but must not inflate the untouched-ground numbers, because the
            # operator can never close it — it isn't ours to test.
            if not grid or _in_grid(host, port):
                totals[state] += 1
            host_touched = host_touched or state in (TESTED, ATTEMPTED)
            port_rows.append({
                "port": port, "state": state,
                "techniques": sum(merged.values()),
                "statuses": merged, "findings": 1 if has_finding else 0,
                "alive": (host, port) in alive,
            })
        hosts_out.append({
            "host": host, "touched": host_touched, "ports": port_rows,
        })

    in_scope_pairs = len(grid)
    touched_pairs = totals[TESTED] + totals[ATTEMPTED]
    summary = {
        "in_scope_pairs": in_scope_pairs,
        "tested": totals[TESTED],
        "attempted": totals[ATTEMPTED],
        "alive_untouched": totals[ALIVE_UNTOUCHED],
        "untouched": totals[UNTOUCHED],
        "coverage_ratio": round(touched_pairs / in_scope_pairs, 3) if in_scope_pairs else None,
        "out_of_scope_targets": sorted(outside_scope),
        "scope_available": bool(scope),
    }
    if not scope:
        summary["limitation"] = (
            "no scope.json in this run dir — the RoE grid is unknown, so coverage is "
            "reported from activity and inventory alone; 'untouched' is unknowable here")
    return {"scope_grid": sorted([h, p] for h, p in grid) if grid else [],
            "hosts": hosts_out, "summary": summary}
