"""AssetInventory — the run's attack-surface map, ARTEX-style ("Enterprise Attack
Surface Discovery"), kept honest by scope.

ARTEX maintains a live asset graph (hosts -> services -> findings). We already have a
KnowledgeGraph for the request-level surface (endpoints/params); what was missing is
the HOST/PORT/SERVICE layer: which in-scope machines answered, on which ports, with
what server banner / page title / auth challenge. That layer is what a RECON
specialist needs first, and what an operator reads to sanity-check the RoE.

Two feeders, one store:
  - PASSIVE: every response on the shared fetch path (tools/http.py) fingerprints its
    target (Server header, <title>, WWW-Authenticate presence). Zero extra requests —
    the surface map builds itself while the team works.
  - ACTIVE: the surface_scan tool sweeps ONLY hosts/ports already in the RoE
    allowlist (it can never widen scope — there is nothing to scan beyond it), and
    the asset-feed importer seeds the same store from an operator-supplied feed.

Storage: inventory.json in the run dir, atomic saves, one RLock — the exploit swarm
writes from several threads concurrently (same discipline as RunManifest).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from pathlib import Path

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _short_title(body: str) -> str:
    m = _TITLE_RE.search(body or "")
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:120]


class AssetInventory:
    """Thread-safe, persisted host->service map for one run."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._data: dict = {"hosts": {}}
        self._load()

    # -- persistence -----------------------------------------------------------

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("hosts"), dict):
                self._data = raw
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass

    def _save_locked(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            tmp.replace(self._path)  # atomic: a concurrent API reader never sees a torn file
        except Exception:
            pass  # evidence best-effort; never break the run over a save

    # -- writers ---------------------------------------------------------------

    def observe_http(self, host: str, port: int, scheme: str, status: int,
                     headers: dict | None = None, body: str = "",
                     source: str = "http") -> None:
        """Fingerprint one observed response (passive — no request is made here)."""
        headers = headers or {}
        server = str(headers.get("Server") or headers.get("server") or "")
        title = _short_title(body or "")
        auth = any(k.lower() == "www-authenticate" for k in (headers or {}))
        key = f"{scheme}/{port}"
        with self._lock:
            host_rec = self._data["hosts"].setdefault(str(host), {"services": {}})
            svc = host_rec["services"].setdefault(key, {
                "port": int(port), "scheme": scheme, "first_seen": _now(),
                "hits": 0, "status_last": None, "server": "", "title": "",
                "auth": False, "source": source,
            })
            svc["hits"] += 1
            svc["last_seen"] = _now()
            if status:
                svc["status_last"] = int(status)
            if server:
                svc["server"] = server[:80]
            if title:
                svc["title"] = title
            if auth:
                svc["auth"] = True
            svc["source"] = source if svc.get("source") in ("", "http") else svc["source"]
            self._save_locked()

    def observe_asset(self, host: str, port: int, scheme: str = "",
                      service: str = "", source: str = "asset_feed") -> None:
        """Register an operator/importer-declared asset WITHOUT any request."""
        key = f"{scheme or 'tcp'}/{port}"
        with self._lock:
            host_rec = self._data["hosts"].setdefault(str(host), {"services": {}})
            svc = host_rec["services"].setdefault(key, {
                "port": int(port), "scheme": scheme or "tcp",
                "first_seen": _now(), "hits": 0, "status_last": None,
                "server": "", "title": "", "auth": False, "source": source,
            })
            if service and not svc.get("title"):
                svc["title"] = service[:120]
            svc["last_seen"] = _now()
            self._save_locked()

    # -- readers ---------------------------------------------------------------

    def summary(self) -> dict:
        """Compact rollup for briefings/reports: {hosts: N, services: M,
        endpoints: [{host, port, scheme, title?, server?}, ...] (bounded)."""
        with self._lock:
            hosts = self._data["hosts"]
            endpoints = []
            for host, rec in sorted(hosts.items()):
                for key, svc in sorted(rec["services"].items()):
                    endpoints.append({
                        "host": host, "port": svc["port"], "scheme": svc["scheme"],
                        "status": svc.get("status_last"), "title": svc.get("title", ""),
                        "server": svc.get("server", ""), "auth": svc.get("auth", False),
                        "source": svc.get("source", ""),
                    })
            return {
                "hosts": len(hosts),
                "services": len(endpoints),
                "endpoints": endpoints[:64],
                "truncated": len(endpoints) > 64,
            }

    def known_hosts(self) -> list[str]:
        with self._lock:
            return sorted(self._data["hosts"].keys())
