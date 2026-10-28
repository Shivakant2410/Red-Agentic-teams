"""LocalSemanticBackend: zero-dependency semantic memory (JSON + hashing embeddings)."""

from __future__ import annotations

import json

from redteam.memory import ExperienceStore
from redteam.memory_backend.local_semantic import (HashingEmbedder,
                                                   LocalSemanticBackend)


def test_hashing_embedder_deterministic_and_normalized():
    e = HashingEmbedder()
    a = e.embed("bypass authentication on the admin panel")
    b = e.embed("bypass authentication on the admin panel")
    c = e.embed("quarterly revenue spreadsheet")
    assert a == b                              # deterministic across calls
    assert len(a) == 512
    assert abs(sum(x * x for x in a) - 1.0) < 1e-6   # normalized
    assert sum(x * y for x, y in zip(a, c)) < 0.2    # unrelated -> near-orthogonal


def test_semantic_recall_finds_related_lesson():
    e = HashingEmbedder()
    be = LocalSemanticBackend("/tmp/never-used-local-semantic.json", embedder=e)
    be.save([
        {"id": "l1", "text": "auth bypass via default credentials on admin panel",
         "kind": "technique", "tags": ["auth"], "utility": 1.0, "uses": 1,
         "helped": 1, "support": 1, "created": "t", "last_used": "t"},
        {"id": "l2", "text": "rate limit resets after token refresh",
         "kind": "observation", "tags": ["ratelimit"], "utility": 1.0, "uses": 1,
         "helped": 0, "support": 1, "created": "t", "last_used": "t"},
    ])
    hits = be.semantic_recall_lessons("how to bypass admin authentication", k=2)
    assert hits and hits[0]["id"] == "l1"
    # load() must NOT leak the internal embedding column
    rows = be.load()
    assert all("embedding" not in r for r in rows)
    assert len(rows) == 2


def test_recall_skips_unrelated_below_noise_floor():
    e = HashingEmbedder()
    be = LocalSemanticBackend("/tmp/never-used-local-semantic-2.json", embedder=e)
    be.save([{"id": "l1", "text": "sql injection in search box", "kind": "technique",
              "tags": [], "utility": 1.0, "uses": 0, "helped": 0, "support": 1,
              "created": "t", "last_used": "t"}])
    assert be.semantic_recall_lessons("quarterly revenue spreadsheet") == []


def test_patterns_learn_and_recall(tmp_path):
    e = HashingEmbedder()
    path = tmp_path / "semantic.json"
    be = LocalSemanticBackend(path, embedder=e)
    be.learn_pattern("JWT session cookies with sequential sub claims", tags=["jwt"])
    be.learn_pattern("SPA frontend calls /api/v2/* behind an API gateway", tags=["api"])

    # persisted across instances
    be2 = LocalSemanticBackend(path, embedder=e)
    hits = be2.recall_patterns("JWT session cookies", k=2)
    assert hits and "JWT" in hits[0]["description"]
    # duplicate learn is a no-op
    be2.learn_pattern("JWT session cookies with sequential sub claims", tags=["jwt"])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["patterns"]) == 2


def test_embedder_failure_degrades_to_plain_json(tmp_path):
    class Exploding:
        dim = 512

        def embed(self, text):
            raise RuntimeError("model missing")

    path = tmp_path / "semantic.json"
    be = LocalSemanticBackend(path, embedder=Exploding())
    be.save([{"id": "l1", "text": "x", "kind": "technique", "tags": [], "utility": 1.0,
              "uses": 0, "helped": 0, "support": 1, "created": "t", "last_used": "t"}])
    assert be.semantic_recall_lessons("anything") == []
    assert be.recall_patterns("anything") == []
    rows = be.load()
    assert len(rows) == 1 and rows[0]["text"] == "x"   # persistence still works


def test_experience_store_end_to_end_with_local_backend(tmp_path):
    be = LocalSemanticBackend(tmp_path / "semantic.json", embedder=HashingEmbedder())
    store = ExperienceStore(tmp_path / "experience.json", backend=be)
    store.learn("Found that default creds work on staging admin panels",
                kind="technique", tags=["auth", "default-creds"])
    briefing = store.briefing(query="authentication bypass on admin interface")
    assert "default creds" in briefing   # via tag or semantic recall
    # the store flushes to its backend on every learn — no explicit save needed
    store2 = ExperienceStore(tmp_path / "experience.json",
                             backend=LocalSemanticBackend(tmp_path / "semantic.json",
                                                          embedder=HashingEmbedder()))
    assert any("default creds" in l.text for l in store2.all())
