"""RECON V2 asset intelligence layer.

Assets are the entity view over the EvidenceStore: domains, subdomains, IPs,
ASNs, services, technologies, certificates, DNS records and cloud assets with
RELATIONSHIPS between them (domain -> dns_record -> ip -> asn -> service, the
Amass/OAM pattern). Every asset carries provenance, confidence, first/last
seen, validation status, scope status and evidence references — because it IS
an Observation with a relationship graph around it.

Scope discipline (directive §4): attribution never widens scope. A discovered
third-party host (e.g. a subdomain that resolves to someone else's cloud) is
recorded with its honest scope_status and an explicit relationship to the
in-scope domain; it is NOT added to the authorized scope.
"""
from __future__ import annotations

from .evidence_store import EvidenceStore
from .observations import (
    KIND_ASN, KIND_CERTIFICATE, KIND_CLOUD_ASSET, KIND_DNS_RECORD, KIND_DOMAIN,
    KIND_IP, KIND_SERVICE, KIND_SUBDOMAIN, KIND_TECHNOLOGY,
    PROVENANCE_ACTIVE, PROVENANCE_PASSIVE, SCOPE_IN,
)

RELATIONS = {
    "domain": ("has_subdomain", "resolves_to", "issued_certificate",
               "hosts_service", "uses_technology"),
    "resolves_to": ("ip",),
    "issued_certificate": ("certificate",),
    "hosts_service": ("service",),
    "uses_technology": ("technology",),
    "belongs_to_asn": ("asn",),
    "in_cloud_account": ("cloud_asset",),
}

HOST_ASSET_KINDS = (KIND_DOMAIN, KIND_SUBDOMAIN, KIND_IP)


class AssetIntelligence:
    """Relationship-aware view over the EvidenceStore."""

    def __init__(self, store: EvidenceStore, scope=None):
        self._store = store
        self._scope = scope
        self._edges: dict[str, list[dict]] = {}   # obs_id -> [{rel, to}]

    def record(self, kind: str, key: str, *, tool: str, provenance: str,
               attrs: dict | None = None, evidence: list | None = None,
               related_to: str = "", relation: str = "") -> str:
        """Record (or merge) one asset; optionally link it to another asset.
        Returns the observation id."""
        obs = self._store.observe(
            kind, key, tool=tool, provenance=provenance,
            attrs=dict(attrs or {}), evidence=evidence,
            related=([related_to] if related_to else []))
        if related_to and relation:
            self.link(related_to, relation, obs.id)
        return obs.id

    def link(self, from_obs_id: str, relation: str, to_obs_id: str) -> None:
        """Record a directed relationship between two assets (idempotent)."""
        if not from_obs_id or not to_obs_id:
            return
        edges = self._edges.setdefault(from_obs_id, [])
        if not any(e["rel"] == relation and e["to"] == to_obs_id for e in edges):
            edges.append({"rel": relation, "to": to_obs_id})

    def edges_for(self, obs_id: str) -> list[dict]:
        return list(self._edges.get(obs_id, []))

    def graph_view(self, *, scope_status: str | None = None,
                   limit: int = 500) -> dict:
        """Nodes + edges in scope-first order: the asset map the operator (and
        downstream specialists) actually consume."""
        obs = self._store.query(asset_kinds=True, limit=limit)
        if scope_status:
            obs = [o for o in obs if o.scope_status == scope_status]
        by_id = {o.id: o for o in obs}
        nodes = []
        for o in obs:
            nodes.append({
                "id": o.id, "kind": o.kind, "key": o.subject,
                "provenance": o.provenance, "confidence": o.confidence,
                "validation_status": o.validation_status,
                "scope_status": o.scope_status,
                "first_seen": o.first_seen, "last_seen": o.last_seen,
                "evidence_count": len(o.evidence_refs),
            })
        edges = []
        for oid, es in self._edges.items():
            for e in es:
                if oid in by_id and e["to"] in by_id:
                    edges.append({"from": oid, "rel": e["rel"], "to": e["to"]})
        return {"nodes": nodes, "edges": edges}

    def attribute_scope(self, key: str) -> str:
        """Re-run scope attribution for an asset key (e.g. after the operator
        narrows/widens the RoE). Never widens scope: only returns in_scope when
        the signed scope authority matches."""
        from .evidence_store import scope_status_for
        for kind in HOST_ASSET_KINDS + (KIND_SERVICE, KIND_TECHNOLOGY):
            hits = self._store.query(kind=kind, subject_contains=key, limit=5)
            for obs in hits:
                if obs.subject == key:
                    return scope_status_for(self._scope, obs.kind, key)
        from .observations import SCOPE_UNATTRIBUTED
        return SCOPE_UNATTRIBUTED

    def summary(self) -> dict:
        stats = self._store.stats()
        in_scope = len(self._store.query(asset_kinds=True,
                                         scope_status="in_scope", limit=9999))
        return {"assets": stats.get("observations", 0),
                "in_scope": in_scope,
                "by_kind": stats.get("by_kind", {}),
                "corroborated": stats.get("corroborated", 0)}
