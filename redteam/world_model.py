"""Typed, evidence-backed application world model.

This is an additive semantic layer over KnowledgeGraph, not a second graph or
an execution engine. It records what the engagement has observed about
principals, business entities, workflow states/transitions, components, layers,
and trust boundaries. It never performs network activity and never authorizes
a test.

Model-generated facts remain explicitly inferred; independent evidence
and the existing verification pipeline retain their own authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit
from typing import Any

from .errors import record_suppressed_error

WORLD_MODEL_SCHEMA_VERSION = 1

PRINCIPAL = "principal"
BUSINESS_ENTITY = "business_entity"
WORKFLOW_STATE = "workflow_state"
WORKFLOW_TRANSITION = "workflow_transition"
APP_COMPONENT = "app_component"
ARCHITECTURE_LAYER = "architecture_layer"
TRUST_BOUNDARY = "trust_boundary"

WORLD_MODEL_KINDS = frozenset({
    PRINCIPAL, BUSINESS_ENTITY, WORKFLOW_STATE, WORKFLOW_TRANSITION,
    APP_COMPONENT, ARCHITECTURE_LAYER, TRUST_BOUNDARY,
})
EPISTEMIC_STATES = frozenset({"observed", "inferred", "operator_supplied"})

_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|authorization|cookie|session_cookie|"
    r"api[_-]?key|private[_-]?key|credential|dpop|csrf[_-]?token)",
    re.IGNORECASE,
)
_MAX_KEY = 240
_MAX_TEXT = 1200
_MAX_REFS = 32
_SECRET_VALUE = re.compile(
    r"\b(?:bearer|basic)\s+[^\s,;]{12,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"\b(?:sk|rk|pk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{16,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|\b[A-Za-z0-9_-]{48,}\b",
    re.IGNORECASE,
)


class WorldModelError(ValueError):
    """A malformed or ungrounded world-model fact."""


def _text(value: Any, field: str, limit: int = _MAX_TEXT) -> str:
    value = str(value or "").strip()
    if not value:
        raise WorldModelError(f"{field} is required")
    if len(value) > limit:
        raise WorldModelError(f"{field} exceeds {limit} characters")
    return value


def _opaque_ref(value: str, field: str) -> str:
    """Accept a named handle, not token-shaped session material."""
    value = _text(value, field, _MAX_KEY)
    low = value.lower()
    token_shaped = (
        low.startswith(("bearer ", "basic "))
        or value.count(".") == 2 and len(value) > 40
        or "=" in value
        or len(value) > 96
    )
    if token_shaped:
        raise WorldModelError(f"{field} must be an opaque session-store reference, not credential material")
    return value


def _safe_value(value: Any, depth: int = 0) -> Any:
    """Bound metadata to JSON-safe scalars/containers; never retain secrets by value."""
    if depth > 3:
        return "<depth-limited>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        clipped = value[:_MAX_TEXT]
        return "<withheld>" if _SECRET_VALUE.search(clipped) else clipped
    if isinstance(value, (list, tuple)):
        return [_safe_value(v, depth + 1) for v in list(value)[:32]]
    if isinstance(value, dict):
        clean = {}
        for key, item in list(value.items())[:64]:
            name = str(key)[:80]
            if _SECRET_KEY.search(name):
                clean[name] = "<withheld>"
            else:
                clean[name] = _safe_value(item, depth + 1)
        return clean
    return str(value)[:_MAX_TEXT]


def _evidence_refs(refs: list[dict] | None) -> list[dict]:
    """Require traceable evidence and normalize refs without copying raw payloads."""
    if not isinstance(refs, list) or not refs:
        raise WorldModelError("at least one evidence reference is required")
    out = []
    seen = set()
    for ref in refs[:_MAX_REFS]:
        if not isinstance(ref, dict):
            raise WorldModelError("evidence references must be objects")
        identity = (ref.get("evidence_id") or ref.get("artifact_ref")
                    or ref.get("ref") or ref.get("id"))
        if not identity:
            raise WorldModelError("each evidence reference needs evidence_id/artifact_ref/ref/id")
        identity = str(identity)[:_MAX_KEY]
        if identity in seen:
            continue
        seen.add(identity)
        clean = {"evidence_id": identity}
        for key in ("kind", "source", "tool", "ts", "artifact_ref"):
            if key in ref and not _SECRET_KEY.search(key):
                clean[key] = _safe_value(ref[key])
        out.append(clean)
    if not out:
        raise WorldModelError("no usable evidence references")
    return out


class WorldModel:
    """Typed facade over the run's existing KnowledgeGraph.

    graph must expose KnowledgeGraph.observe() and nodes(). Fact IDs are
    stable graph node IDs (kind:key). Relations are descriptive only: they
    do not confer authorization, ownership, or permission to execute.
    """

    def __init__(self, graph, audit=None):
        if graph is None or not callable(getattr(graph, "observe", None)):
            raise WorldModelError("a KnowledgeGraph-compatible graph is required")
        self.graph = graph
        self.audit = audit

    def _record(
        self, kind: str, key: str, attrs: dict, *, source: str,
        evidence_refs: list[dict], epistemic_state: str = "observed",
        relate_to: str | None = None, relation: str = "relates_to",
    ) -> dict:
        if kind not in WORLD_MODEL_KINDS:
            raise WorldModelError(f"unsupported world-model kind: {kind}")
        key = _text(key, "key", _MAX_KEY)
        source = _text(source, "source", 120)
        if epistemic_state not in EPISTEMIC_STATES:
            raise WorldModelError(f"invalid epistemic_state: {epistemic_state}")
        if re.search(r"(llm|model|reason|thesis)", source, re.IGNORECASE) and epistemic_state == "observed":
            epistemic_state = "inferred"
        refs = _evidence_refs(evidence_refs)
        safe_attrs = _safe_value(attrs)
        safe_attrs.update({
            "world_model_schema": WORLD_MODEL_SCHEMA_VERSION,
            "epistemic_state": epistemic_state,
            "evidence_ref_ids": [r["evidence_id"] for r in refs],
        })
        node = self.graph.observe(
            kind, key, attrs=safe_attrs, source=source,
            relate_to=relate_to, relation=relation, evidence_refs=refs,
            edge_evidence=refs if relate_to else None,
        )
        result = {
            "id": getattr(node, "id", f"{kind}:{key}"),
            "kind": kind,
            "key": key,
            "epistemic_state": epistemic_state,
            "evidence_refs": refs,
        }
        if self.audit is not None:
            try:
                self.audit.record("world_model.fact_recorded", **result, source=source)
            except Exception as exc:
                record_suppressed_error(self.audit, "world_model", "audit_fact_recorded", exc)
        return result

    def record_principal(
        self, principal_ref: str, *, role: str, evidence_refs: list[dict],
        source: str, session_ref: str = "", tenant_ref: str = "",
        epistemic_state: str = "observed",
    ) -> dict:
        """Record an opaque test principal; session_ref must not be a credential."""
        attrs = {"role": _text(role, "role", 120)}
        if session_ref:
            attrs["session_ref"] = _opaque_ref(session_ref, "session_ref")
        if tenant_ref:
            attrs["tenant_ref"] = _text(tenant_ref, "tenant_ref", _MAX_KEY)
        return self._record(
            PRINCIPAL, principal_ref, attrs, source=source,
            evidence_refs=evidence_refs, epistemic_state=epistemic_state,
        )

    def record_entity(
        self, entity_ref: str, *, entity_type: str, evidence_refs: list[dict],
        source: str, owner_ref: str = "", tenant_ref: str = "",
        attributes: dict | None = None, epistemic_state: str = "observed",
    ) -> dict:
        # Caller metadata is merged first; reserved identity fields are written
        # last so an untrusted attribute map cannot overwrite the typed contract.
        attrs = _safe_value(attributes or {})
        if not isinstance(attrs, dict):
            raise WorldModelError("attributes must be an object")
        attrs["entity_type"] = _text(entity_type, "entity_type", 120)
        if tenant_ref:
            attrs["tenant_ref"] = _text(tenant_ref, "tenant_ref", _MAX_KEY)
        return self._record(
            BUSINESS_ENTITY, entity_ref, attrs, source=source,
            evidence_refs=evidence_refs, epistemic_state=epistemic_state,
            relate_to=(f"{PRINCIPAL}:{owner_ref}" if owner_ref else None),
            relation="owns_or_controls",
        )

    def record_workflow_transition(
        self, entity_ref: str, *, action: str, from_state: str, to_state: str,
        evidence_refs: list[dict], source: str, actor_ref: str = "",
        outcome: str = "", epistemic_state: str = "observed",
    ) -> dict:
        action = _text(action, "action", 240)
        from_state = _text(from_state, "from_state", 120)
        to_state = _text(to_state, "to_state", 120)
        actor_ref = str(actor_ref or "").strip()[:_MAX_KEY]
        entity_ref = _text(entity_ref, "entity_ref", _MAX_KEY)
        identity = "\x1f".join((entity_ref, action, from_state, to_state, actor_ref))
        transition_key = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        attrs = {
            "entity_ref": entity_ref,
            "action": action,
            "from_state": from_state,
            "to_state": to_state,
            "actor_ref": actor_ref,
            "outcome": str(outcome or "")[:240],
        }
        return self._record(
            WORKFLOW_TRANSITION, transition_key, attrs, source=source,
            evidence_refs=evidence_refs, epistemic_state=epistemic_state,
            relate_to=f"{BUSINESS_ENTITY}:{entity_ref}",
            relation="has_observed_transition",
        )

    def record_workflow_state(
        self, entity_ref: str, state: str, *, evidence_refs: list[dict],
        source: str, epistemic_state: str = "observed",
    ) -> dict:
        entity_ref = _text(entity_ref, "entity_ref", _MAX_KEY)
        state = _text(state, "state", 120)
        key = f"{entity_ref}#{state}"
        return self._record(
            WORKFLOW_STATE, key,
            {"entity_ref": entity_ref, "state": state},
            source=source, evidence_refs=evidence_refs,
            epistemic_state=epistemic_state,
            relate_to=f"{BUSINESS_ENTITY}:{entity_ref}",
            relation="has_observed_state",
        )

    def record_architecture_layer(
        self, layer_ref: str, *, name: str, evidence_refs: list[dict],
        source: str, epistemic_state: str = "inferred",
    ) -> dict:
        return self._record(
            ARCHITECTURE_LAYER, layer_ref,
            {"name": _text(name, "name", 120)},
            source=source, evidence_refs=evidence_refs,
            epistemic_state=epistemic_state,
        )

    def record_component(
        self, component_ref: str, *, component_type: str, layer: str,
        evidence_refs: list[dict], source: str,
        epistemic_state: str = "observed",
    ) -> dict:
        return self._record(
            APP_COMPONENT, component_ref,
            {"component_type": _text(component_type, "component_type", 120),
             "layer": _text(layer, "layer", 120)},
            source=source, evidence_refs=evidence_refs,
            epistemic_state=epistemic_state,
        )

    def record_trust_boundary(
        self, boundary_ref: str, *, source_layer: str, destination_layer: str,
        control: str, evidence_refs: list[dict], source: str,
        epistemic_state: str = "inferred",
    ) -> dict:
        return self._record(
            TRUST_BOUNDARY, boundary_ref,
            {"source_layer": _text(source_layer, "source_layer", 120),
             "destination_layer": _text(destination_layer, "destination_layer", 120),
             "control": _text(control, "control", 300)},
            source=source, evidence_refs=evidence_refs,
            epistemic_state=epistemic_state,
        )

    @staticmethod
    def _route_path(url: str) -> tuple[str, str] | None:
        """Return a credential-free host and route path; query strings are omitted."""
        try:
            parsed = urlsplit(str(url))
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme not in ("http", "https") or not host:
                return None
            port = parsed.port
        except (TypeError, ValueError):
            return None
        default_port = 443 if parsed.scheme == "https" else 80
        host_ref = f"{host}:{port}" if port and port != default_port else host
        path = parsed.path or "/"
        if _SECRET_VALUE.search(path):
            path = "/<redacted>"
        path = re.sub(r"/[0-9a-fA-F]{24,}(?=/|$)", "/{opaque}", path)
        path = re.sub(r"/\d{2,}(?=/|$)", "/{id}", path)
        return host_ref[:_MAX_KEY], path[:600]

    def ingest_recon_store(self, evidence_store, *, limit: int = 2000) -> int:
        """Project observed RECON V2 assets into typed application components."""
        if evidence_store is None or not callable(getattr(evidence_store, "query", None)):
            return 0
        accepted = {"domain", "subdomain", "host", "ip", "service", "endpoint",
                    "page", "technology", "api_spec"}
        layers = {"domain": "network", "subdomain": "network", "host": "network",
                  "ip": "network", "service": "service", "endpoint": "application",
                  "page": "application", "technology": "application", "api_spec": "application"}
        count = 0
        for obs in evidence_store.query(limit=limit):
            kind = str(getattr(obs, "kind", "") or "")
            subject = str(getattr(obs, "subject", "") or "")
            if kind not in accepted or not subject:
                continue
            if "://" in subject:
                route = self._route_path(subject)
                if route is None:
                    continue
                subject = f"{route[0]}{route[1]}"
            refs = list(getattr(obs, "evidence_refs", []) or [])
            if not refs:
                refs = [{"evidence_id": f"recon:{getattr(obs, 'id', subject)}",
                         "kind": "recon_observation"}]
            tool = str(getattr(obs, "tool", "") or "recon_v2")[:80]
            self.record_component(
                f"recon:{kind}:{subject}", component_type=kind,
                layer=layers[kind], evidence_refs=refs,
                source=f"recon_v2:{tool}", epistemic_state="observed",
            )
            count += 1
        return count

    def ingest_traffic_records(self, records: list[dict] | None, *, limit: int = 2000) -> int:
        """Project browser/proxy/extension exchanges without retaining raw payloads."""
        count = 0
        for row in (records or [])[:limit]:
            if not isinstance(row, dict):
                continue
            route = self._route_path(row.get("url", ""))
            if route is None:
                continue
            try:
                seq = int(row.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if seq <= 0:
                continue
            host_ref, path = route
            source = str(row.get("source") or row.get("tool") or "traffic")[:80]
            refs = [{"evidence_id": f"traffic_seq:{seq}", "kind": "http_exchange",
                     "source": source, "tool": str(row.get("tool") or source)[:80]}]
            method = str(row.get("method") or "GET").upper()[:12]
            self.record_component(
                f"traffic:host:{host_ref}", component_type="http_host", layer="network",
                evidence_refs=refs, source=f"traffic:{source}", epistemic_state="observed",
            )
            self.record_component(
                f"traffic:endpoint:{host_ref}:{method}:{path}",
                component_type="http_endpoint", layer="application",
                evidence_refs=refs, source=f"traffic:{source}", epistemic_state="observed",
            )
            try:
                status = int(row.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            if status in (401, 403):
                self.record_trust_boundary(
                    f"http-auth-boundary:{host_ref}:{path}",
                    source_layer="client", destination_layer="application",
                    control=f"HTTP {status} response observed at {method} {path}",
                    evidence_refs=refs, source=f"traffic:{source}",
                    epistemic_state="inferred",
                )
            count += 1
        return count

    def refresh_from_sources(self, evidence_store=None, traffic_path=None) -> dict:
        """Refresh the typed projection from the run's existing evidence sources."""
        recon_count = self.ingest_recon_store(evidence_store)
        traffic_count = 0
        if traffic_path is not None:
            try:
                from .traffic import read_traffic
                traffic_count = self.ingest_traffic_records(
                    read_traffic(traffic_path, after=0, limit=5000), limit=5000)
            except (OSError, ValueError) as exc:
                record_suppressed_error(self.audit, "world_model", "refresh_traffic", exc)
        return {"recon_components": recon_count, "traffic_components": traffic_count}

    def compact_projection(self, *, max_facts: int = 80, max_chars: int = 6000) -> dict:
        """Small typed projection for thesis generation; no raw bodies or cookies."""
        allowed_attrs = {
            "role", "tenant_ref", "entity_type", "component_type", "layer",
            "name", "source_layer", "destination_layer", "control", "action",
            "from_state", "to_state", "outcome", "state", "epistemic_state",
        }
        facts = []
        for node in self.graph.nodes():
            if getattr(node, "kind", "") not in WORLD_MODEL_KINDS:
                continue
            attrs = _safe_value(getattr(node, "attrs", {}) or {})
            fact = {
                "id": getattr(node, "id", ""), "kind": node.kind,
                "key": node.key,
                "epistemic_state": attrs.get("epistemic_state", "observed"),
                "evidence_ref_ids": list(attrs.get("evidence_ref_ids", []))[:8],
                "attributes": {k: v for k, v in attrs.items() if k in allowed_attrs},
            }
            candidate = facts + [fact]
            if len(candidate) > max_facts or len(json.dumps(candidate, ensure_ascii=False)) > max_chars:
                break
            facts.append(fact)
        return {"schema_version": WORLD_MODEL_SCHEMA_VERSION, "facts": facts}

    def snapshot(self) -> dict:
        """Return a compact, deterministic projection; never includes raw secrets."""
        rows = []
        for node in self.graph.nodes():
            if getattr(node, "kind", "") not in WORLD_MODEL_KINDS:
                continue
            attrs = _safe_value(getattr(node, "attrs", {}) or {})
            rows.append({
                "id": getattr(node, "id", ""),
                "kind": node.kind,
                "key": node.key,
                "attrs": attrs,
                "confidence": getattr(node, "confidence", "observed"),
                "lifecycle": getattr(node, "lifecycle", {}) or {},
            })
        rows.sort(key=lambda row: (row["kind"], row["key"]))
        return {"schema_version": WORLD_MODEL_SCHEMA_VERSION, "facts": rows}
