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
import re
from typing import Any

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


class WorldModelError(ValueError):
    """A malformed or ungrounded world-model fact."""


def _text(value: Any, field: str, limit: int = _MAX_TEXT) -> str:
    value = str(value or "").strip()
    if not value:
        raise WorldModelError(f"{field} is required")
    if len(value) > limit:
        raise WorldModelError(f"{field} exceeds {limit} characters")
    return value


def _safe_value(value: Any, depth: int = 0) -> Any:
    """Bound metadata to JSON-safe scalars/containers; never retain secrets by value."""
    if depth > 3:
        return "<depth-limited>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_MAX_TEXT]
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
            except Exception:
                pass
        return result

    def record_principal(
        self, principal_ref: str, *, role: str, evidence_refs: list[dict],
        source: str, session_ref: str = "", tenant_ref: str = "",
        epistemic_state: str = "observed",
    ) -> dict:
        """Record an opaque test principal; session_ref must not be a credential."""
        attrs = {"role": _text(role, "role", 120)}
        if session_ref:
            attrs["session_ref"] = _text(session_ref, "session_ref", _MAX_KEY)
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
        attrs = {"entity_type": _text(entity_type, "entity_type", 120)}
        if tenant_ref:
            attrs["tenant_ref"] = _text(tenant_ref, "tenant_ref", _MAX_KEY)
        attrs.update(_safe_value(attributes or {}))
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
