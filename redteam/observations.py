"""ObservationLog — the shared evidence plane for reconnaissance.

One OBSERVATION is one claim a tool or specialist makes about the target,
carrying full provenance and a validation lifecycle. The log is append-only
JSONL (last record per obs_id wins on load), duplicates merge by
(type, target, method) WITHOUT destroying provenance, and every observation
is mirrored into the run's KnowledgeGraph so downstream specialists
(EXPLOIT / LOGIC / VERIFY) see exactly the same state — this log is not a
second store of truth, it is the provenance/validation layer over the graph.

Validation states (honest by default):

    discovered -> awaiting_corroboration -> corroborated | contradicted
               -> unverifiable | stale

A tool's unverified output NEVER reaches "corroborated" by itself: the state
either advances when a SECOND DISTINCT source tool observes the same key
(mirroring KnowledgeGraph.observe's own corroboration rule) or when
CrossCheckTool writes its verdict via mark_validation(). Verdicts land in the
log AND the audit trail — never in the finding pipeline (a corroborated lead
is still a lead, see tools/crosscheck.py).

Every observation carries:
    obs_id, type, target, method, scheme, port, source_tool,
    source_specialist, ts (observation timestamp), mode
    ("passive" = no target contact, e.g. DNS/cert;
     "light" = metadata-class wire touch, e.g. robots/sitemap/headers;
     "active" = interactive discovery),
    evidence_refs (artifact references), confidence, validation, metadata.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime as _dt, timezone as _tz
from pathlib import Path
from urllib.parse import urlsplit

# Validation lifecycle (the one vocabulary for observation corroboration).
VALIDATION_STATES = ("discovered", "awaiting_corroboration", "corroborated",
                     "contradicted", "unverifiable", "stale")

# Crosscheck verdicts may move a lead to these states only.
VERDICT_STATES = ("corroborated", "contradicted", "unverifiable")

# Observation types and the KnowledgeGraph node kind each mirrors to.
OBS_TYPES = {
    "endpoint": "endpoint",        # a URL discovered on/for the surface
    "parameter": "parameter",      # a query/body/header parameter
    "technology": "technology",    # server/framework/CMS/library fingerprint
    "service": "service",          # scheme/host/port answering
    "host": "host",                # a hostname observed in scope
    "domain": "domain",            # DNS-level relationship (SAN, CNAME, MX...)
    "form": None,                  # a form/input map (kept in metadata only)
    "api_spec": "technology",      # an OpenAPI/Swagger/GraphQL surface clue
    "console_error": None,         # browser console/page error (metadata only)
    "header": None,                # security-relevant header/cookie attribute
    "asset": None,                 # JS asset / source map / sitemap entry
}
KG_KINDS = {"host", "service", "endpoint", "parameter", "technology", "domain"}
MODES = ("passive", "light", "active")

_METADATA_LIMIT_CHARS = 4096
_SECRET_KEY_MARKERS = ("password", "passwd", "secret", "token", "authorization",
                       "cookie", "api_key", "apikey", "session", "credential")


def _now() -> str:
    return _dt.now(_tz.utc).isoformat()


def _clip(value, limit: int = 512) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + f"…(+{len(text) - limit})"


def _clean_metadata(metadata: dict | None) -> dict:
    """Bound and secret-hygiene the metadata block: clip values, drop keys
    that look credential-shaped by NAME (values are never stored for them)."""
    clean: dict = {}
    for key, value in (metadata or {}).items():
        if any(marker in str(key).lower() for marker in _SECRET_KEY_MARKERS):
            clean[str(key)[:64]] = "<withheld>"
            continue
        clean[str(key)[:64]] = _clip(value)
    return clean


def _obs_key(obs_type: str, target: str, method: str) -> str:
    return f"{obs_type}|{target}|{(method or '').upper()}"


def _obs_id(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class Observation:
    obs_id: str
    type: str
    target: str
    method: str = ""
    scheme: str = ""
    port: int | None = None
    source_tool: str = ""
    source_specialist: str = ""
    ts: str = ""
    last_seen: str = ""
    mode: str = "active"
    confidence: str = "observed"          # observed | corroborated (KG vocabulary)
    validation: str = "discovered"
    metadata: dict = field(default_factory=dict)
    evidence_refs: list = field(default_factory=list)
    provenance: list = field(default_factory=list)   # every (ts, tool) sighting
    history: list = field(default_factory=list)      # validation transitions

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, row: dict) -> "Observation":
        fields = {f for f in cls.__dataclass_fields__}  # noqa: C416
        return cls(**{k: v for k, v in row.items() if k in fields})


class ObservationLog:
    """Append-only observation store with provenance-preserving merges.

    Persistence: every mutation appends the FULL current record; load folds
    by obs_id (last wins). A torn trailing line is skipped on load — the
    journal/traffic files stay the wire authority; this file is the
    correlation layer."""

    def __init__(self, path, graph=None, audit=None):
        self.path = Path(path)
        self._graph = graph
        self._audit = audit
        self._lock = threading.Lock()
        self._obs: dict[str, Observation] = {}
        self._load()

    # -- persistence ------------------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace") \
                .splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue                      # torn tail: skip, fold continues
            if isinstance(row, dict) and row.get("obs_id"):
                self._obs[row["obs_id"]] = Observation.from_dict(row)

    def _append(self, obs: Observation) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(obs.to_dict(), default=str) + "\n")
            os.replace(tmp, self.path)
        except OSError:
            # Best-effort persistence: the KG mirror and audit record still
            # carry the observation; never crash a specialist on a sink error.
            pass

    # -- mutation ---------------------------------------------------------------

    def record(self, obs_type: str, target: str, *, method: str = "",
               scheme: str = "", port: int | None = None,
               source_tool: str = "", source_specialist: str = "",
               mode: str = "active", metadata: dict | None = None,
               evidence_refs: list | None = None) -> dict:
        """Record (or merge) one observation. Returns the stored dict.

        Merge rule: same (type, target, method) is the SAME observation —
        last_seen and provenance grow, first_seen/obs_id never change, and a
        second DISTINCT source tool advances validation to 'corroborated'
        (matching KnowledgeGraph.observe's own corroboration rule). A
        contradicted observation that re-observes honestly returns to
        'discovered' (the contradiction was about the earlier evidence)."""
        if obs_type not in OBS_TYPES:
            raise ValueError(f"unknown observation type {obs_type!r} "
                             f"(known: {sorted(OBS_TYPES)})")
        if mode not in MODES:
            raise ValueError(f"unknown observation mode {mode!r} (known: {MODES})")
        target = _clip(target, 2000)
        method = (method or "").upper()[:16]
        key = _obs_key(obs_type, target, method)
        now = _now()
        with self._lock:
            obs = self._obs.get(_obs_id(key))
            fresh = obs is None
            if fresh:
                obs = Observation(
                    obs_id=_obs_id(key), type=obs_type, target=target,
                    method=method, scheme=str(scheme or "")[:16],
                    port=int(port) if port else None,
                    source_tool=str(source_tool)[:64],
                    source_specialist=str(source_specialist)[:64],
                    ts=now, last_seen=now, mode=mode,
                    metadata=_clean_metadata(metadata),
                    evidence_refs=list(evidence_refs or [])[:32],
                    provenance=[{"ts": now, "tool": str(source_tool)[:64]}],
                    history=[{"ts": now, "state": "discovered",
                              "by": str(source_tool)[:64], "reason": "first seen"}])
                self._obs[obs.obs_id] = obs
            else:
                obs.last_seen = now
                sighting = {"ts": now, "tool": str(source_tool)[:64]}
                if sighting not in obs.provenance:
                    obs.provenance.append(sighting)
                    obs.provenance = obs.provenance[-64:]
                distinct_tools = {p["tool"] for p in obs.provenance} - {""}
                if metadata:
                    merged = dict(obs.metadata)
                    merged.update(_clean_metadata(metadata))
                    obs.metadata = {k: merged[k] for k in sorted(merged)}
                for ref in (evidence_refs or []):
                    if ref not in obs.evidence_refs:
                        obs.evidence_refs.append(ref)
                obs.evidence_refs = obs.evidence_refs[:32]
                if (len(distinct_tools) >= 2
                        and obs.validation in ("discovered",
                                               "awaiting_corroboration")):
                    self._transition(obs, "corroborated",
                                     by=f"multi-source:{','.join(sorted(distinct_tools))[:120]}",
                                     reason="second independent source observed "
                                            "the same key")
                if obs.validation == "contradicted":
                    self._transition(obs, "discovered",
                                     by=str(source_tool)[:64],
                                     reason="re-observed after contradiction")
            stored = obs.to_dict()
            self._append(obs)
        self._mirror(obs_type, target, method, obs)
        if self._audit is not None:
            self._audit.record("observation.recorded", obs_type=obs_type,
                               target=_clip(target, 200), mode=mode,
                               obs_id=obs.obs_id, validation=obs.validation,
                               fresh=fresh,
                               source_tool=str(source_tool)[:64])
        return stored

    def mark_validation(self, obs_id: str, state: str, *, by: str,
                        reason: str = "") -> dict | None:
        """Move one observation to a crosscheck verdict state (or stale).
        Only VERDICT_STATES + 'stale' are accepted here; anything else must
        come from record()'s own rules."""
        if state not in VERDICT_STATES and state != "stale":
            raise ValueError(f"mark_validation accepts {VERDICT_STATES + ('stale',)}, "
                             f"got {state!r}")
        with self._lock:
            obs = self._obs.get(obs_id)
            if obs is None:
                return None
            self._transition(obs, state, by=str(by)[:64], reason=reason[:300])
            stored = obs.to_dict()
            self._append(obs)
        if self._audit is not None:
            self._audit.record("observation.validation", obs_id=obs_id,
                               state=state, by=str(by)[:64], reason=reason[:200])
        return stored

    def _transition(self, obs: Observation, state: str, *, by: str,
                    reason: str) -> None:
        if state == obs.validation:
            return
        obs.validation = state
        obs.confidence = "corroborated" if state == "corroborated" else \
            obs.confidence
        obs.history.append({"ts": _now(), "state": state, "by": by,
                            "reason": reason})
        obs.history = obs.history[-32:]

    def _mirror(self, obs_type: str, target: str, method: str,
                obs: Observation) -> None:
        """Mirror into the run's KnowledgeGraph (the specialists' shared view).
        Non-graph types (form/console_error/header/asset) stay log-only."""
        kind = OBS_TYPES.get(obs_type)
        if kind is None or self._graph is None:
            return
        attrs: dict = {"mode": obs.mode, "validation": obs.validation,
                       "source_tool": obs.source_tool}
        if obs_type == "parameter":
            key = target
        elif method and method not in ("GET", ""):
            attrs["method"] = method
            key = target
        else:
            key = target
        try:
            self._graph.observe(kind, key, attrs=attrs,
                                source=obs.source_tool or "observations",
                                evidence_refs=obs.evidence_refs or None)
        except Exception:  # noqa: BLE001 — graph sink must never break recon
            pass

    # -- reads --------------------------------------------------------------------

    def get(self, obs_id: str) -> dict | None:
        with self._lock:
            obs = self._obs.get(obs_id)
            return obs.to_dict() if obs else None

    def filter(self, *, obs_type: str = "", validation: str = "",
               mode: str = "", target_contains: str = "",
               limit: int = 200) -> list[dict]:
        with self._lock:
            rows = [o.to_dict() for o in self._obs.values()]
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        out = []
        for row in rows:
            if obs_type and row["type"] != obs_type:
                continue
            if validation and row["validation"] != validation:
                continue
            if mode and row["mode"] != mode:
                continue
            if target_contains and target_contains.lower() not in row["target"].lower():
                continue
            out.append({k: row[k] for k in
                        ("obs_id", "type", "target", "method", "mode",
                         "source_tool", "ts", "last_seen", "validation",
                         "confidence")})
            if len(out) >= max(1, min(limit, 500)):
                break
        return out

    def stats(self) -> dict:
        with self._lock:
            rows = list(self._obs.values())
        by_type: dict[str, int] = {}
        by_validation: dict[str, int] = {}
        by_mode: dict[str, int] = {}
        for o in rows:
            by_type[o.type] = by_type.get(o.type, 0) + 1
            by_validation[o.validation] = by_validation.get(o.validation, 0) + 1
            by_mode[o.mode] = by_mode.get(o.mode, 0) + 1
        return {"total": len(rows), "by_type": by_type,
                "by_validation": by_validation, "by_mode": by_mode}

    def pending_corroboration(self, limit: int = 100) -> list[dict]:
        """Discovered/awaiting leads — the honest 'unverified' bucket for the
        recon handoff (never counted as confirmed anywhere)."""
        rows = self.filter(validation="discovered", limit=limit) + \
            self.filter(validation="awaiting_corroboration", limit=limit)
        return rows[:limit]
