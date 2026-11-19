"""RECON V2 — specialized, evidence-first reconnaissance subsystem.

Public surface:
  - observations / evidence_store / assets / workspace / adapters / capabilities
  - build_recon_v2(out_dir, scope, limiter, audit, traffic) -> ReconV2 bundle

The bundle is the single wiring point used by run.py: one EvidenceStore, one
AssetIntelligence view, one EvidenceWorkspace, one ProjectDiscoveryAdapter —
all sharing the run's scope authority and request budget.
"""
from __future__ import annotations

from pathlib import Path

from .adapters import AdapterError, ProjectDiscoveryAdapter
from .assets import AssetIntelligence
from .capabilities import (
    api_recon, dns_cert_intel, external_asset_intel, js_recon,
    record_page_evidence, validate_and_attribute,
)
from .evidence_store import EvidenceStore, scope_status_for
from .observations import (
    Observation, EvidenceRef, observation_id,
)
from .workspace import EvidenceWorkspace

__all__ = [
    "AdapterError", "ProjectDiscoveryAdapter", "AssetIntelligence",
    "EvidenceStore", "EvidenceWorkspace", "Observation", "EvidenceRef",
    "observation_id", "api_recon", "dns_cert_intel", "external_asset_intel",
    "js_recon", "record_page_evidence", "validate_and_attribute",
    "scope_status_for", "build_recon_v2",
]


class ReconV2:
    """The run-scoped bundle every capability shares."""

    def __init__(self, store: EvidenceStore, assets: AssetIntelligence,
                 workspace: EvidenceWorkspace,
                 adapter: ProjectDiscoveryAdapter | None):
        self.store = store
        self.assets = assets
        self.workspace = workspace
        self.adapter = adapter

    def handoff(self) -> dict:
        """The structured RECON → downstream handoff artifact."""
        return self.store.handoff_summary()

    def stats(self) -> dict:
        return self.workspace.stats()


def build_recon_v2(out_dir, scope, limiter, audit, traffic=None,
                   sandbox_exec=None) -> ReconV2:
    out_dir = Path(out_dir)
    store = EvidenceStore(out_dir / "evidence.jsonl", scope=scope)
    assets = AssetIntelligence(store, scope=scope)
    workspace = EvidenceWorkspace(
        store,
        traffic_path=(out_dir / "traffic.jsonl") if traffic is not None else None,
        annotations_path=out_dir / "annotations.jsonl")
    adapter = None
    if limiter is not None:
        adapter = ProjectDiscoveryAdapter(store, scope, limiter, audit,
                                          sandbox_exec=sandbox_exec)
    return ReconV2(store, assets, workspace, adapter)
