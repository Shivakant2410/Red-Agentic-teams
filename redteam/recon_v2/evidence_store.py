"""RECON V2 shared evidence store.

Append-only JSONL store of Observations with a query layer that recon
capabilities and agent tools share. This is the "agent-readable evidence
workspace" substrate: search without rereading raw logs, dedupe by stable
identity, correlate by subject, corroborate across independent sources.

Design rules (matching the repo's telemetry conventions):
  - appending never breaks a run (swallow + count, like TrafficRecorder);
  - flushes are atomic (tmp + replace, like KnowledgeGraph);
  - loads are tolerant of torn lines;
  - scope attribution is conservative: a subject is `in_scope` only when the
    signed ScopeGuard says so; everything else stays out_of_scope /
    unattributed and is never auto-promoted (directive §4).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .observations import (
    CONFIDENCE_CORROBORATED, HOST_KINDS, KIND_ASN, KIND_CERTIFICATE,
    KIND_CLOUD_ASSET, KIND_DNS_RECORD, KIND_DOMAIN, KIND_ENDPOINT, KIND_IP,
    KIND_PAGE, KIND_SERVICE, KIND_SUBDOMAIN, KIND_TECHNOLOGY, Observation,
    SCOPE_IN, SCOPE_OUT, SCOPE_UNATTRIBUTED, VALIDATION_CORROBORATED,
    VALIDATION_UNVALIDATED, merge_observation,
)

ASSET_KINDS = (KIND_DOMAIN, KIND_SUBDOMAIN, KIND_IP, KIND_ASN, KIND_SERVICE,
               KIND_CERTIFICATE, KIND_DNS_RECORD, KIND_CLOUD_ASSET,
               KIND_TECHNOLOGY)


def scope_status_for(scope, kind: str, subject: str) -> str:
    """Conservative scope attribution for a subject.

    - host-like subjects (domain/subdomain/ip): name-based check against the
      signed allowlist + exclusions (no DNS — attribution is about AUTHORITY,
      not reachability);
    - URL-like subjects: defer to the ScopeGuard itself (cheap, no resolution
      of our own — ScopeGuard.check resolves; here we only need the authority
      answer, so host extraction + host check is the honest cheap proxy);
    - no scope authority attached → unattributed.
    """
    if scope is None:
        return SCOPE_UNATTRIBUTED
    try:
        if kind in HOST_KINDS:
            return SCOPE_IN if scope.host_scope_status(subject) else SCOPE_OUT
        if "://" in subject:
            return SCOPE_IN if scope.host_scope_status(scope.host_of(subject)) else SCOPE_OUT
        return SCOPE_UNATTRIBUTED
    except Exception:
        return SCOPE_OUT   # fail closed: unattributable ⇒ not authorized


class EvidenceStore:
    """Append-only Observation store with query/dedupe/correlate/corroborate."""

    def __init__(self, path=None, scope=None, clock=None, max_observations: int = 20000):
        self._path = Path(path) if path else None
        self._scope = scope
        self._clock = clock or (lambda: None)
        self._max = int(max_observations)
        self._lock = threading.Lock()
        self._by_id: dict[str, Observation] = {}
        self.count = 0

    # -- write path ----------------------------------------------------------
    def add(self, obs: Observation) -> Observation:
        """Add (or merge into an existing) observation. Returns the stored one."""
        with self._lock:
            if not obs.scope_status or obs.scope_status == SCOPE_UNATTRIBUTED:
                if self._scope is not None:
                    obs.scope_status = scope_status_for(self._scope, obs.kind,
                                                        obs.subject)
            existing = self._by_id.get(obs.id)
            if existing is not None:
                merge_observation(existing, obs)
                self._persist(existing)
                return existing
            if len(self._by_id) >= self._max:
                # Bounded store: the oldest observation is evicted (recon is a
                # living view, not an unbounded archive — raw logs stay the
                # archive; this store stays searchable).
                try:
                    oldest = min(self._by_id.values(), key=lambda o: o.first_seen)
                    self._by_id.pop(oldest.id, None)
                except Exception:
                    pass
            self._by_id[obs.id] = obs
            self.count += 1
            self._persist(obs)
            return obs

    def observe(self, kind: str, subject: str, *, tool: str, provenance: str,
                attrs: dict | None = None, origin: str = "agent",
                evidence: list | None = None, related: list | None = None) -> Observation:
        from .observations import EvidenceRef
        obs = Observation(
            kind=kind, subject=subject, attrs=dict(attrs or {}), tool=tool,
            origin=origin, provenance=provenance,
            evidence_refs=[(r.to_json() if isinstance(r, EvidenceRef) else dict(r))
                           for r in (evidence or [])],
            related=list(related or []),
        )
        return self.add(obs)

    def corroborate(self, obs_id: str, ref: dict | None = None) -> Observation | None:
        """Record an INDEPENDENT second source for an observation: upgrades
        confidence + validation. A source that merely re-states the first one
        (same tool) does not corroborate — callers must pass the second
        producer's evidence ref."""
        with self._lock:
            obs = self._by_id.get(obs_id)
        if obs is None:
            return None
        if ref:
            obs.evidence_refs.append(dict(ref))
        if obs.validation_status in (VALIDATION_UNVALIDATED, VALIDATION_CORROBORATED):
            obs.validation_status = VALIDATION_CORROBORATED
        obs.confidence = CONFIDENCE_CORROBORATED
        self._persist(obs)
        return obs

    # -- read path -----------------------------------------------------------
    def get(self, obs_id: str) -> Observation | None:
        return self._by_id.get(obs_id)

    def query(self, *, kind: str | None = None, kinds: tuple | None = None,
              subject_contains: str = "", tool: str = "", provenance: str = "",
              validation: str = "", scope_status: str = "",
              asset_kinds: bool = False, limit: int = 50) -> list[Observation]:
        """Filtered, newest-first view. Compact — the agent-facing search."""
        sel = kinds or ((ASSET_KINDS if asset_kinds else None) if kind is None
                        else (kind,))
        out = []
        for obs in self._by_id.values():
            if sel and obs.kind not in sel:
                continue
            if subject_contains and subject_contains.lower() not in obs.subject.lower():
                continue
            if tool and obs.tool != tool:
                continue
            if provenance and obs.provenance != provenance:
                continue
            if validation and obs.validation_status != validation:
                continue
            if scope_status and obs.scope_status != scope_status:
                continue
            out.append(obs)
        out.sort(key=lambda o: o.last_seen, reverse=True)
        return out[: max(1, int(limit))]

    def correlate(self, subject: str, limit: int = 50) -> dict:
        """Everything the store knows ABOUT one subject, across capabilities —
        the correlation view (DNS record + IP + cert + service + endpoints...)."""
        obs = self.query(subject_contains=subject, limit=limit)
        return {
            "subject": subject,
            "observations": [o.to_json() for o in obs],
            "kinds": sorted({o.kind for o in obs}),
            "tools": sorted({o.tool for o in obs if o.tool}),
            "corroborated": sum(1 for o in obs
                                if o.validation_status == VALIDATION_CORROBORATED),
        }

    def dedupe_report(self) -> dict:
        """How many raw adds folded into how many stored observations."""
        return {"stored": len(self._by_id), "adds": self.count}

    def stats(self) -> dict:
        by_kind: dict[str, int] = {}
        by_prov: dict[str, int] = {}
        by_scope: dict[str, int] = {}
        corroborated = 0
        for obs in self._by_id.values():
            by_kind[obs.kind] = by_kind.get(obs.kind, 0) + 1
            by_prov[obs.provenance] = by_prov.get(obs.provenance, 0) + 1
            by_scope[obs.scope_status] = by_scope.get(obs.scope_status, 0) + 1
            if obs.validation_status in (VALIDATION_CORROBORATED, "confirmed"):
                corroborated += 1
        return {"observations": len(self._by_id), "by_kind": by_kind,
                "by_provenance": by_prov, "by_scope": by_scope,
                "corroborated": corroborated, "adds": self.count}

    def handoff_summary(self) -> dict:
        """The structured RECON → EXPLOIT handoff: in-scope surface only, with
        provenance and evidence pointers (directive §8: useful structured
        discoveries, not narration)."""
        in_scope = self.query(scope_status=SCOPE_IN, limit=2000)
        domains = [o.to_json() for o in in_scope
                   if o.kind in (KIND_DOMAIN, KIND_SUBDOMAIN)]
        endpoints = [o.to_json() for o in in_scope if o.kind == KIND_ENDPOINT]
        services = [o.to_json() for o in in_scope if o.kind == KIND_SERVICE]
        techs = [o.to_json() for o in in_scope if o.kind == KIND_TECHNOLOGY]
        pages = [o.to_json() for o in in_scope if o.kind == KIND_PAGE]
        return {
            "domains": domains,
            "endpoints": endpoints,
            "services": services,
            "technologies": techs,
            "pages": pages,
            "stats": self.stats(),
        }

    # -- persistence ---------------------------------------------------------
    def _persist(self, obs: Observation) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(obs.to_json(), ensure_ascii=False,
                                    default=str) + "\n")
            self.count_written = getattr(self, "count_written", 0) + 1
        except Exception:
            pass   # telemetry must never break a run

    def load(self) -> int:
        """Rehydrate from disk (tolerant of torn lines). Returns count loaded."""
        if self._path is None or not self._path.exists():
            return 0
        loaded = 0
        for line in self._path.read_text(encoding="utf-8",
                                         errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obs = Observation.from_json(json.loads(line))
            except Exception:
                continue
            with self._lock:
                existing = self._by_id.get(obs.id)
                if existing is not None:
                    merge_observation(existing, obs)
                else:
                    self._by_id[obs.id] = obs
            loaded += 1
        return loaded
