"""RECON V2 agent-readable evidence workspace.

The workspace is what lets a RECON specialist inspect its OWN accumulated
evidence without rereading enormous raw logs (directive §6):

  - `search`  — compact filtered view over observations;
  - `inspect` — the full record for one observation id;
  - `traffic_query` — structured filtering over traffic.jsonl (the proxy /
    browser / tool wire evidence) with seq-cursor paging;
  - `annotate` — attach a specialist's note to a wire record or observation;
  - `stats` — what the store holds, by kind/provenance/scope.

Annotations live in `annotations.jsonl` beside the traffic log and are merged
back into query results, so filters like Burp's "Notes" column work over the
same evidence plane the tools write.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from ..traffic import read_traffic
from .evidence_store import EvidenceStore


class EvidenceWorkspace:
    def __init__(self, store: EvidenceStore, traffic_path: str | Path | None = None,
                 annotations_path: str | Path | None = None):
        self._store = store
        self._traffic_path = Path(traffic_path) if traffic_path else None
        self._annotations_path = Path(annotations_path) if annotations_path else None
        self._lock = threading.Lock()
        self._annotations: dict[str, dict] = {}   # key "traffic:<seq>"/"obs:<id>" -> note

    # -- observations --------------------------------------------------------
    def search(self, *, kind: str = "", subject_contains: str = "", tool: str = "",
               provenance: str = "", validation: str = "",
               scope_status: str = "", asset_kinds: bool = False,
               limit: int = 40) -> list[dict]:
        """Compact rows for the agent: id, kind, subject, one-line summary."""
        obs = self._store.query(
            kind=kind or None, subject_contains=subject_contains, tool=tool,
            provenance=provenance, validation=validation,
            scope_status=scope_status, asset_kinds=asset_kinds, limit=limit)
        rows = []
        for o in obs:
            summary_bits = [f"{k}={v}" for k, v in list(o.attrs.items())[:3]]
            note = self._annotations.get(f"obs:{o.id}", {})
            rows.append({
                "id": o.id, "kind": o.kind, "subject": o.subject,
                "summary": " ".join(summary_bits)[:120],
                "tool": o.tool, "provenance": o.provenance,
                "validation": o.validation_status, "scope": o.scope_status,
                "evidence_refs": len(o.evidence_refs),
                "note": note.get("note", ""),
            })
        return rows

    def inspect(self, obs_id: str) -> dict | None:
        obs = self._store.get(obs_id)
        if obs is None:
            return None
        data = obs.to_json()
        data["annotation"] = self._annotations.get(f"obs:{obs_id}", {}).get("note", "")
        return data

    def correlate(self, subject: str) -> dict:
        return self._store.correlate(subject)

    # -- traffic -------------------------------------------------------------
    def traffic_query(self, *, host: str = "", contains: str = "",
                      method: str = "", status: int | None = None,
                      tool: str = "", source: str = "",
                      after_seq: int = 0, limit: int = 40) -> list[dict]:
        """Structured filter over the wire-evidence log (proxy + browser +
        tools all land here). Returns compact rows with their seq cursor."""
        if self._traffic_path is None:
            return []
        rows = read_traffic(self._traffic_path, after=after_seq, limit=20000)
        out = []
        for rec in rows:
            if host and host.lower() not in str(rec.get("url", "")).lower():
                continue
            if contains and contains.lower() not in json.dumps(
                    {k: rec.get(k) for k in ("req_body", "resp_body", "url")},
                    default=str).lower():
                continue
            if method and str(rec.get("method", "")).upper() != method.upper():
                continue
            if status is not None and rec.get("status") != status:
                continue
            if tool and rec.get("tool") != tool:
                continue
            if source and rec.get("source") != source:
                continue
            seq = rec.get("seq")
            note = self._annotations.get(f"traffic:{seq}", {})
            out.append({
                "seq": seq, "ts": rec.get("ts"), "tool": rec.get("tool"),
                "source": rec.get("source"), "method": rec.get("method"),
                "url": str(rec.get("url", ""))[:200],
                "status": rec.get("status"), "error": rec.get("error", ""),
                "req_body_len": len(str(rec.get("req_body") or "")),
                "resp_body_len": len(str(rec.get("resp_body") or "")),
                "note": note.get("note", ""),
            })
            if len(out) >= limit:
                break
        return out

    def traffic_row(self, seq: int) -> dict | None:
        """Full wire record for one seq (replay's input)."""
        if self._traffic_path is None:
            return None
        for rec in read_traffic(self._traffic_path, after=seq - 1, limit=1):
            if rec.get("seq") == seq:
                return rec
        return None

    # -- annotations ---------------------------------------------------------
    def annotate(self, key: str, note: str, author: str = "") -> bool:
        """Attach a note to `traffic:<seq>` or `obs:<id>` (Burp-style Notes)."""
        note = str(note or "").strip()
        if not note:
            return False
        rec = {"key": key, "note": note[:2000], "author": author,
               "ts": _now_iso()}
        with self._lock:
            self._annotations[key] = rec
            if self._annotations_path is not None:
                try:
                    self._annotations_path.parent.mkdir(parents=True, exist_ok=True)
                    with self._annotations_path.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                except Exception:
                    pass   # telemetry never breaks the run
        return True

    def load_annotations(self) -> int:
        if self._annotations_path is None or not self._annotations_path.exists():
            return 0
        n = 0
        for line in self._annotations_path.read_text(
                encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                self._annotations[rec["key"]] = rec
                n += 1
            except Exception:
                continue
        return n

    def stats(self) -> dict:
        data = self._store.stats()
        data["traffic_records"] = len(read_traffic(self._traffic_path or "",
                                                   after=0, limit=10**9)) \
            if self._traffic_path and self._traffic_path.exists() else 0
        data["annotations"] = len(self._annotations)
        return data


def _now_iso() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).isoformat()
