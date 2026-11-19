"""RECON V2 shared observation schema.

Every reconnaissance capability — external asset intelligence, DNS/certificate
intel, network discovery, browser recon, proxy/traffic intel, API recon,
JavaScript recon, authenticated mapping — emits ONE record type: an
`Observation`. A single schema is what makes evidence searchable, dedupable,
correlatable and corroborable across capabilities (the Amass/ARTEX lesson: a
persistent, attributed, pipeline-normalized asset model beats per-tool dumps).

An Observation carries the fields the directive requires for every asset:

  - provenance            passive | active | imported | derived
  - confidence            observed | corroborated   (mirrors KnowledgeGraph)
  - first_seen / last_seen
  - validation_status     unvalidated | corroborated | confirmed | refuted
  - scope_status          in_scope | out_of_scope | unattributed
  - evidence_refs         pointers at traffic.jsonl, audit, screenshots, ...

Scope attribution is deliberately conservative: only subjects the signed
ScopeGuard accepts are `in_scope`; third-party assets discovered passively are
`out_of_scope` (or `unattributed` when no scope authority is attached) and are
NEVER auto-promoted into the authorized scope (directive §4).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

# --- provenance ---------------------------------------------------------------
PROVENANCE_PASSIVE = "passive"     # observed without touching the target
PROVENANCE_ACTIVE = "active"       # observed by acting on the target
PROVENANCE_IMPORTED = "imported"   # operator feed / third-party dataset
PROVENANCE_DERIVED = "derived"     # computed from other observations

PROVENANCES = (PROVENANCE_PASSIVE, PROVENANCE_ACTIVE, PROVENANCE_IMPORTED,
               PROVENANCE_DERIVED)

# --- confidence (vocabulary shared with knowledge.py) -------------------------
CONFIDENCE_OBSERVED = "observed"
CONFIDENCE_CORROBORATED = "corroborated"

# --- validation ---------------------------------------------------------------
VALIDATION_UNVALIDATED = "unvalidated"
VALIDATION_CORROBORATED = "corroborated"
VALIDATION_CONFIRMED = "confirmed"
VALIDATION_REFUTED = "refuted"

# --- scope --------------------------------------------------------------------
SCOPE_IN = "in_scope"
SCOPE_OUT = "out_of_scope"
SCOPE_UNATTRIBUTED = "unattributed"

# --- observation kinds --------------------------------------------------------
KIND_DOMAIN = "domain"
KIND_SUBDOMAIN = "subdomain"
KIND_IP = "ip"
KIND_ASN = "asn"
KIND_SERVICE = "service"
KIND_ENDPOINT = "endpoint"
KIND_TECHNOLOGY = "technology"
KIND_CERTIFICATE = "certificate"
KIND_DNS_RECORD = "dns_record"
KIND_CLOUD_ASSET = "cloud_asset"
KIND_CONSOLE_ERROR = "console_error"
KIND_SCREENSHOT = "screenshot"
KIND_JS_ENDPOINT = "js_endpoint"
KIND_API_SPEC = "api_spec"
KIND_PAGE = "page"

KINDS = (KIND_DOMAIN, KIND_SUBDOMAIN, KIND_IP, KIND_ASN, KIND_SERVICE,
         KIND_ENDPOINT, KIND_TECHNOLOGY, KIND_CERTIFICATE, KIND_DNS_RECORD,
         KIND_CLOUD_ASSET, KIND_CONSOLE_ERROR, KIND_SCREENSHOT,
         KIND_JS_ENDPOINT, KIND_API_SPEC, KIND_PAGE)

# Host-like kinds whose subject is a bare hostname (scope checks by host).
HOST_KINDS = (KIND_DOMAIN, KIND_SUBDOMAIN, KIND_IP)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class EvidenceRef:
    """A pointer at inspectable evidence backing one observation."""
    kind: str            # traffic | audit | screenshot | graph | finding | tool | event
    ref: str             # e.g. "traffic.jsonl#seq=12", "screenshots/x.png", "audit#event=..."
    tool: str = ""
    ts: str = ""

    def to_json(self) -> dict:
        return {"kind": self.kind, "ref": self.ref, "tool": self.tool, "ts": self.ts}

    @classmethod
    def from_json(cls, data: dict) -> "EvidenceRef":
        return cls(kind=str(data.get("kind", "")), ref=str(data.get("ref", "")),
                   tool=str(data.get("tool", "")), ts=str(data.get("ts", "")))


@dataclass
class Observation:
    kind: str                       # one of KINDS
    subject: str                    # canonical subject (host, url, ip, asn, ...)
    attrs: dict = field(default_factory=dict)
    tool: str = ""                  # producing tool/capability
    origin: str = "agent"           # agent | system | external
    provenance: str = PROVENANCE_ACTIVE
    confidence: str = CONFIDENCE_OBSERVED
    validation_status: str = VALIDATION_UNVALIDATED
    scope_status: str = SCOPE_UNATTRIBUTED
    first_seen: str = ""
    last_seen: str = ""
    evidence_refs: list = field(default_factory=list)   # [EvidenceRef.to_json()]
    related: list = field(default_factory=list)         # [observation ids]
    id: str = ""

    def __post_init__(self):
        if not self.first_seen:
            self.first_seen = _now()
        self.last_seen = self.last_seen or self.first_seen
        if not self.id:
            self.id = observation_id(self.kind, self.subject, self.tool, self.attrs)

    def to_json(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "subject": self.subject,
            "attrs": self.attrs, "tool": self.tool, "origin": self.origin,
            "provenance": self.provenance, "confidence": self.confidence,
            "validation_status": self.validation_status,
            "scope_status": self.scope_status,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "evidence_refs": self.evidence_refs, "related": self.related,
        }

    @classmethod
    def from_json(cls, data: dict) -> "Observation":
        return cls(
            kind=str(data.get("kind", "")), subject=str(data.get("subject", "")),
            attrs=dict(data.get("attrs") or {}), tool=str(data.get("tool", "")),
            origin=str(data.get("origin", "agent")),
            provenance=str(data.get("provenance", PROVENANCE_ACTIVE)),
            confidence=str(data.get("confidence", CONFIDENCE_OBSERVED)),
            validation_status=str(data.get("validation_status", VALIDATION_UNVALIDATED)),
            scope_status=str(data.get("scope_status", SCOPE_UNATTRIBUTED)),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
            evidence_refs=list(data.get("evidence_refs") or []),
            related=list(data.get("related") or []),
            id=str(data.get("id", "")),
        )


def observation_id(kind: str, subject: str, tool: str, attrs: dict | None) -> str:
    """Stable identity: the same (kind, subject, tool, salient attrs) pair seen
    again dedupes into the same observation instead of growing the store."""
    salient = ""
    if attrs:
        try:
            salient = json.dumps(attrs, sort_keys=True, default=str)
        except Exception:
            salient = str(attrs)
    digest = hashlib.sha256(
        f"{kind}|{subject}|{tool}|{salient}".encode("utf-8")).hexdigest()[:16]
    return f"obs-{digest}"


def merge_observation(existing: Observation, incoming: Observation) -> Observation:
    """Fold an incoming observation into the stored one (dedupe semantics).

    - first_seen keeps the EARLIEST, last_seen the LATEST;
    - evidence refs merge idempotently;
    - confidence upgrades observed→corroborated when the second source is an
      INDEPENDENT producer (different tool, not just a re-run);
    - validation never regresses (corroborated/confirmed stay until explicitly
      refuted); related links union.
    """
    if incoming.first_seen < existing.first_seen:
        existing.first_seen = incoming.first_seen
    if incoming.last_seen > existing.last_seen:
        existing.last_seen = incoming.last_seen
    seen_refs = {json.dumps(r, sort_keys=True) for r in existing.evidence_refs}
    for ref in incoming.evidence_refs:
        key = json.dumps(ref, sort_keys=True)
        if key not in seen_refs:
            existing.evidence_refs.append(ref)
            seen_refs.add(key)
    if (incoming.tool and existing.tool and incoming.tool != existing.tool
            and existing.confidence == CONFIDENCE_OBSERVED):
        existing.confidence = CONFIDENCE_CORROBORATED
        if existing.validation_status == VALIDATION_UNVALIDATED:
            existing.validation_status = VALIDATION_CORROBORATED
    for rel in incoming.related:
        if rel not in existing.related:
            existing.related.append(rel)
    existing.last_seen = max(existing.first_seen, existing.last_seen)
    return existing
