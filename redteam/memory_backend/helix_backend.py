"""HelixBackend — a graph+vector Backend for ExperienceStore, plus AppPattern storage.

Implements memory.py's Backend protocol (load/save) so ExperienceStore works with this
backend exactly as it does with LocalJSONBackend today — no changes needed to existing
tag-scored recall. On top of that, it adds what a flat JSON file structurally cannot do:
semantic (vector) search over Lesson text AND a second node kind, AppPattern, for the
facts that are actually missing today — "what does this app's shape look like, and what
worked on apps shaped like it" — distilled from each run's KnowledgeGraph/audit log before
that graph is discarded (see reflect_app_patterns in app_patterns.py).

CAVEAT (tested, not assumed): the official ghcr.io/helixdb/helixdb:v0.0.3 Docker image
did not persist data to a mounted volume across container restarts in local testing here
(writes made before a restart were gone after it, regardless of mount path or settle
time). Until that's root-caused (image bug vs. undocumented config), this backend gives
real semantic recall WITHIN one HelixServer container's uptime, but is not yet durable
across a stopped/restarted container the way the "persistent memory" goal implies. Treat
it as a within-session upgrade for now; LocalJSONBackend remains the durable default.
"""

from __future__ import annotations

import time
from dataclasses import asdict

from .embedder import EMBEDDING_DIM, Embedder

LESSON_LABEL = "Lesson"
APP_PATTERN_LABEL = "AppPattern"
_INDEX_RETRIES = 15
_INDEX_RETRY_DELAY = 0.5


class HelixBackend:
    """Backend for ExperienceStore, backed by a running HelixServer."""

    def __init__(self, client, embedder: Embedder | None = None):
        self._client = client
        self._embedder = embedder or Embedder()
        self._ensured_indexes = False

    # -- memory.Backend protocol (Lesson rows) ----------------------------------

    def load(self) -> list[dict]:
        import helixdb as hx
        rb = (hx.read_batch()
             .var_as("all", hx.g().n_with_label(LESSON_LABEL)
                     .value_map(["text", "kind", "tags", "utility", "uses", "helped",
                                "support", "id", "created", "last_used"]))
             .returning(["all"]))
        result = self._client.query(rb.to_query_request())
        rows = []
        for row in result.get("all", []):
            row = dict(row)
            row["tags"] = list(row.get("tags") or [])
            rows.append(row)
        return rows

    def save(self, rows: list[dict]) -> None:
        """Full replace, matching LocalJSONBackend's save-the-whole-set contract: clear
        existing Lesson nodes, then re-insert. Simple and correct for ExperienceStore's
        call volume (dozens-hundreds of lessons, not a high-frequency append log)."""
        import helixdb as hx
        existing = self._client.query(
            hx.read_batch().var_as("ids", hx.g().n_with_label(LESSON_LABEL).id())
            .returning(["ids"]).to_query_request())
        for item in existing.get("ids", []):
            node_id = item.get("$id") if isinstance(item, dict) else item
            if node_id is not None:
                self._client.query(
                    hx.write_batch().var_as(
                        "d", hx.g().n(hx.NodeRef.id(node_id)).drop()
                    ).returning(["d"]).to_query_request())

        if not rows:
            return
        self._ensure_indexes()
        texts = [r["text"] for r in rows]
        embeddings = self._embedder.embed_many(texts)
        batch = hx.write_batch()
        for i, (row, emb) in enumerate(zip(rows, embeddings)):
            props = dict(row)
            props["tags"] = list(props.get("tags") or [])
            props["embedding"] = emb
            batch = batch.var_as(f"n{i}", hx.g().add_n(LESSON_LABEL, props))
        self._client.query(batch.returning([f"n{i}" for i in range(len(rows))]).to_query_request())

    # -- semantic recall (what LocalJSONBackend cannot do) ----------------------

    def semantic_recall_lessons(self, query: str, k: int = 5) -> list[dict]:
        import helixdb as hx
        self._ensure_indexes()
        vec = self._embedder.embed(query)
        rb = (hx.read_batch()
             .var_as("hits", hx.g().vector_search_nodes(LESSON_LABEL, "embedding", vec, k)
                     .value_map(["text", "kind", "tags", "id"]))
             .returning(["hits"]))
        result = self._retry_on_index_not_ready(rb)
        return result.get("hits", [])

    def learn_pattern(self, description: str, tags: list[str] | None = None) -> None:
        """Store an APP-SHAPE fact distilled from a run — the piece ExperienceStore's
        tag-scored Lesson recall has no equivalent for. See app_patterns.py."""
        import helixdb as hx
        self._ensure_indexes()
        emb = self._embedder.embed(description)
        batch = hx.write_batch().var_as(
            "p", hx.g().add_n(APP_PATTERN_LABEL,
                              {"description": description, "tags": list(tags or []),
                               "embedding": emb}))
        self._client.query(batch.returning(["p"]).to_query_request())

    def recall_patterns(self, query: str, k: int = 3) -> list[dict]:
        import helixdb as hx
        self._ensure_indexes()
        vec = self._embedder.embed(query)
        rb = (hx.read_batch()
             .var_as("hits", hx.g().vector_search_nodes(APP_PATTERN_LABEL, "embedding", vec, k)
                     .value_map(["description", "tags"]))
             .returning(["hits"]))
        result = self._retry_on_index_not_ready(rb)
        return result.get("hits", [])

    # -- internals ----------------------------------------------------------

    def _ensure_indexes(self) -> None:
        if self._ensured_indexes:
            return
        import helixdb as hx
        for label in (LESSON_LABEL, APP_PATTERN_LABEL):
            batch = hx.write_batch().var_as(
                "i", hx.g().create_vector_index_nodes(
                    label, "embedding", EMBEDDING_DIM, hx.VectorDistanceMetric.COSINE))
            try:
                self._client.query(batch.returning(["i"]).to_query_request())
            except Exception:
                pass   # index already exists from a prior call in this session
        self._ensured_indexes = True

    def _retry_on_index_not_ready(self, read_batch) -> dict:
        """Index creation is async server-side (observed: a fresh index needs ~1-2s
        before vector_search_nodes stops raising index_not_found). Retry briefly rather
        than fail a search that will succeed a moment later."""
        last_exc = None
        for _ in range(_INDEX_RETRIES):
            try:
                return self._client.query(read_batch.to_query_request())
            except Exception as exc:
                last_exc = exc
                time.sleep(_INDEX_RETRY_DELAY)
        raise last_exc
