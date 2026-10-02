"""Local text embeddings for semantic memory recall — no API, no network dependency.

A small sentence-transformer running on-device, consistent with this project's
free-tier-only philosophy: OpenRouter calls are rate-limited and cost real wall-clock
(see Phase 5 notes on the daily quota), so the one thing memory recall should NOT depend
on is another network call per lesson stored/recalled.
"""

from __future__ import annotations

# all-MiniLM-L6-v2: 384-dim, ~90MB, fast on CPU — the standard small baseline for
# semantic-similarity tasks; good enough for short tradecraft/pattern descriptions,
# not chosen for leaderboard quality.
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384


class Embedder:
    """Lazily loads the model on first use (not at import time) so importing this module
    never requires the dependency installed unless embeddings are actually requested."""

    def __init__(self, model_name: str = MODEL_NAME):
        self._model_name = model_name
        self._model = None

    def _ensure_loaded(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name)
        return self._model

    def embed(self, text: str) -> list[float]:
        model = self._ensure_loaded()
        vec = model.encode(text, normalize_embeddings=True)
        return [float(x) for x in vec]

    def embed_many(self, texts: list[str]) -> list[list[float]]:
        model = self._ensure_loaded()
        vecs = model.encode(texts, normalize_embeddings=True)
        return [[float(x) for x in v] for v in vecs]
