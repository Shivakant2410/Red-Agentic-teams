"""Asset-feed importer — ARTEX's "ScopeSentry Asset Synchronization", fail-closed.

ARTEX syncs an external asset feed (ScopeSentry: domains, IPs, ports, services) into
the platform before testing. The idea ports directly; the trust model does NOT. A feed
is OPERATOR-SUPPLIED DATA, and the one thing this codebase never does is let data
widen its own authorization. So the importer is an INTERSECTION, not a merge:

  - a feed record is kept only if the ScopeGuard would have allowed a request to it
    anyway (same allowlist/excludes/ports/wildcard logic — we literally call
    scope.check, zero re-implementation, zero drift);
  - everything else is DROPPED and counted, with samples surfaced to the operator;
  - scope.check() on a dropped host still raises afterwards — importing cannot and
    does not expand the RoE.

Accepted shapes (auto-detected by extension/content):
  .json  — [ {host|domain|ip, port, scheme?, service?}, ... ] or {"assets": [...]}
  .jsonl — one JSON object per line, same fields
  .csv   — header row: host|domain|ip, port, scheme?, service?

No network calls happen here — importing only SEEDS the AssetInventory.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..inventory import AssetInventory
from ..scope import ScopeGuard, ScopeViolation

_HOUSING_KEYS = ("host", "domain", "ip", "hostname", "target")
_SERVICE_KEYS = ("service", "name", "banner")


def _pick(rec: dict, *keys: str) -> str:
    for k in keys:
        v = rec.get(k)
        if v not in (None, ""):
            return str(v).strip()
    return ""


def _normalize(raw: dict) -> dict | None:
    host = _pick(raw, *_HOUSING_KEYS)
    if not host:
        return None
    port_s = _pick(raw, "port")
    try:
        port = int(port_s)
    except (TypeError, ValueError):
        port = 0
    scheme = _pick(raw, "scheme", "protocol").lower()
    service = _pick(raw, *_SERVICE_KEYS)
    return {"host": host, "port": port, "scheme": scheme, "service": service}


def load_asset_feed(path: str | Path) -> list[dict]:
    """Parse a feed file into normalized records. Raises ValueError on hopeless
    input (unreadable file, no usable records at all is NOT an error — an empty
    intersection is a valid outcome)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"asset feed unreadable: {exc}") from exc

    records: list[dict] = []
    suffix = p.suffix.lower()
    if suffix == ".csv" or (suffix not in (".json", ".jsonl")
                            and text.lstrip().startswith(("host", "domain", "ip",
                                                          '"host"', '"domain"'))):
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            rec = _normalize({k: v for k, v in row.items() if k})
            if rec:
                records.append(rec)
        return records

    if suffix == ".jsonl":
        lines = text.splitlines()
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # Tolerate a .json extension holding JSONL (common with feed exporters).
            lines = text.splitlines()
        else:
            if isinstance(data, dict) and isinstance(data.get("assets"), list):
                data = data["assets"]
            if not isinstance(data, list):
                raise ValueError("asset feed JSON must be a list of assets "
                                 "or {\"assets\": [...]}")
            for item in data:
                if isinstance(item, dict):
                    rec = _normalize(item)
                    if rec:
                        records.append(rec)
            return records

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and isinstance(item.get("assets"), list):
            item_list = item["assets"]
            for sub in item_list:
                if isinstance(sub, dict):
                    rec = _normalize(sub)
                    if rec:
                        records.append(rec)
            continue
        if isinstance(item, dict):
            rec = _normalize(item)
            if rec:
                records.append(rec)
    return records


def apply_asset_feed(records: list[dict], scope: ScopeGuard,
                     inventory: AssetInventory) -> dict:
    """Intersect the feed with the RoE and seed the inventory. Fail-closed:
    anything the ScopeGuard would refuse is dropped and counted, never widened."""
    stats = {"total": len(records), "imported": 0, "dropped": 0, "no_port": 0,
             "out_of_scope": 0, "dropped_samples": []}
    for rec in records:
        # .get() throughout: apply_asset_feed also accepts RAW feed dicts (hand-built
        # in tests / operator scripts), not only load_asset_feed's normalized output.
        host = str(rec.get("host") or "").strip()
        try:
            port = int(rec.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        scheme = (str(rec.get("scheme") or "").strip() or "http").lower()
        service = str(rec.get("service") or "").strip()
        if not host:
            stats["dropped"] += 1
            if len(stats["dropped_samples"]) < 5:
                stats["dropped_samples"].append("<no host>")
            continue
        if port <= 0:
            stats["no_port"] += 1
            stats["dropped"] += 1
            if len(stats["dropped_samples"]) < 5:
                stats["dropped_samples"].append(f"{host}:<no port>")
            continue
        try:
            # The RoE check itself — the importer has NO matching logic of its own.
            scope.check(f"{scheme}://{host}:{port}/")
        except ScopeViolation:
            stats["out_of_scope"] += 1
            stats["dropped"] += 1
            if len(stats["dropped_samples"]) < 5:
                stats["dropped_samples"].append(f"{host}:{port} (out of scope)")
            continue
        inventory.observe_asset(host, port, scheme=scheme, service=service,
                                source="asset_feed")
        stats["imported"] += 1
    return stats
