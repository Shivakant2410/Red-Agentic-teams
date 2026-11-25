"""Contract tests for the typed application World Model."""
from dataclasses import dataclass, field

import pytest

from redteam.world_model import (
    BUSINESS_ENTITY, PRINCIPAL, TRUST_BOUNDARY, WORKFLOW_TRANSITION,
    WorldModel, WorldModelError,
)


@dataclass
class _Node:
    kind: str
    key: str
    attrs: dict = field(default_factory=dict)
    confidence: str = "observed"
    lifecycle: dict = field(default_factory=dict)

    @property
    def id(self):
        return f"{self.kind}:{self.key}"


class _Graph:
    def __init__(self):
        self.rows = {}
        self.edges = []

    def observe(self, kind, key, attrs=None, source="", relate_to=None,
                relation="has", evidence_refs=None, **kwargs):
        node = self.rows.setdefault((kind, key), _Node(kind, key))
        node.attrs.update(attrs or {})
        if relate_to:
            self.edges.append((relate_to, relation, node.id))
        return node

    def nodes(self):
        return list(self.rows.values())


class _Audit:
    def __init__(self):
        self.events = []

    def record(self, name, **kwargs):
        self.events.append((name, kwargs))


def _refs(*ids):
    return [{"evidence_id": value, "kind": "browser", "source": "test"} for value in ids]


def test_principal_and_owned_entity_are_typed_graph_facts():
    graph = _Graph()
    model = WorldModel(graph)
    principal = model.record_principal(
        "test-user-a", role="member", session_ref="session-ref-a",
        evidence_refs=_refs("obs-1"), source="browser_accessibility",
    )
    entity = model.record_entity(
        "invoice-fixture-17", entity_type="invoice", owner_ref="test-user-a",
        tenant_ref="tenant-fixture", evidence_refs=_refs("obs-2"),
        source="browser_workflow",
    )

    assert principal["id"] == f"{PRINCIPAL}:test-user-a"
    assert entity["id"] == f"{BUSINESS_ENTITY}:invoice-fixture-17"
    assert graph.edges == [
        (f"{PRINCIPAL}:test-user-a", "owns_or_controls",
         f"{BUSINESS_ENTITY}:invoice-fixture-17")
    ]


def test_workflow_transition_is_stable_and_evidence_backed():
    graph = _Graph()
    model = WorldModel(graph)
    first = model.record_workflow_transition(
        "invoice-fixture-17", action="submit_for_approval",
        from_state="draft", to_state="pending",
        actor_ref="test-user-a", outcome="visible status changed",
        evidence_refs=_refs("traffic-42"), source="browser_network",
    )
    second = model.record_workflow_transition(
        "invoice-fixture-17", action="submit_for_approval",
        from_state="draft", to_state="pending",
        actor_ref="test-user-a", outcome="visible status changed",
        evidence_refs=_refs("traffic-42"), source="browser_network",
    )

    assert first["id"] == second["id"]
    assert first["kind"] == WORKFLOW_TRANSITION
    node = graph.rows[(WORKFLOW_TRANSITION, first["key"])]
    assert node.attrs["from_state"] == "draft"
    assert node.attrs["to_state"] == "pending"
    assert node.attrs["epistemic_state"] == "observed"


def test_inferred_boundary_stays_inferred_and_is_not_a_finding():
    graph = _Graph()
    model = WorldModel(graph)
    row = model.record_trust_boundary(
        "edge-to-api", source_layer="edge", destination_layer="api_gateway",
        control="request normalization inferred from response evidence",
        evidence_refs=_refs("exchange-1"), source="reasoning",
    )
    node = graph.rows[(TRUST_BOUNDARY, row["key"])]

    assert row["epistemic_state"] == "inferred"
    assert node.attrs["epistemic_state"] == "inferred"
    assert "confirmed" not in node.attrs


def test_secret_shaped_metadata_is_withheld_in_storage_and_snapshot():
    graph = _Graph()
    model = WorldModel(graph)
    row = model.record_entity(
        "fixture-1", entity_type="workspace",
        attributes={
            "display_name": "test workspace",
            "access_token": "should-not-persist",
            "nested": {"api_key": "also-secret", "tier": "free"},
        },
        evidence_refs=_refs("obs-secret-test"), source="browser",
    )
    snapshot = model.snapshot()
    node = graph.rows[(BUSINESS_ENTITY, "fixture-1")]

    assert node.attrs["access_token"] == "<withheld>"
    assert node.attrs["nested"]["api_key"] == "<withheld>"
    assert "should-not-persist" not in repr(snapshot)
    assert row["id"] == "business_entity:fixture-1"


def test_facts_require_evidence_and_known_epistemic_state():
    model = WorldModel(_Graph())
    with pytest.raises(WorldModelError, match="evidence reference"):
        model.record_entity(
            "fixture-1", entity_type="workspace", evidence_refs=[],
            source="browser",
        )
    with pytest.raises(WorldModelError, match="epistemic_state"):
        model.record_entity(
            "fixture-1", entity_type="workspace", evidence_refs=_refs("obs-1"),
            source="browser", epistemic_state="confirmed",
        )


def test_snapshot_is_sorted_and_schema_versioned():
    graph = _Graph()
    model = WorldModel(graph)
    model.record_trust_boundary(
        "z-boundary", source_layer="api", destination_layer="worker",
        control="queue handoff", evidence_refs=_refs("obs-z"), source="recon",
    )
    model.record_entity(
        "a-entity", entity_type="project", evidence_refs=_refs("obs-a"),
        source="browser",
    )

    snapshot = model.snapshot()
    assert snapshot["schema_version"] == 1
    assert [row["key"] for row in snapshot["facts"]] == ["a-entity", "z-boundary"]
