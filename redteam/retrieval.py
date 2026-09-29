"""Semantic retrieval over the template catalog — built in memory, stored nowhere.

Keyword/IDF search can only match words that literally appear. It cannot tell that a
CVE template *is about* Grafana when the name says "Dashboard LFI". Latent Semantic
Indexing (TF-IDF + truncated SVD) fixes much of that by learning which terms co-occur,
so a query lands near related documents even without an exact term match.

Two deliberate choices:
  - **Nothing is persisted.** The index is built lazily in memory from the catalog the
    first time a query needs it (~seconds) and discarded with the process. A search index
    should not become another database to maintain.
  - **Hybrid scoring.** Semantic similarity alone drifts; exact terms ("jira", "CVE-2021")
    matter a lot in security. We combine the lexical IDF score with the semantic score.

Degrades gracefully: if scikit-learn is unavailable, callers fall back to lexical search.
"""

from __future__ import annotations

SKLEARN_AVAILABLE = True
try:  # pragma: no cover - environment dependent
    from sklearn.decomposition import TruncatedSVD
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import normalize
except ImportError:  # pragma: no cover
    SKLEARN_AVAILABLE = False


class SemanticIndex:
    """In-memory LSI index over short documents (template names/tags/paths)."""

    def __init__(self, components: int = 160, min_df: int = 1):
        self._components = components
        self._min_df = min_df
        self._vec = None
        self._svd = None
        self._docs = None      # reduced, L2-normalized document matrix
        self.ready = False

    def fit(self, documents: list[str]) -> "SemanticIndex":
        if not SKLEARN_AVAILABLE or not documents:
            self.ready = False
            return self
        self._vec = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2),
                                    min_df=self._min_df, max_features=120000,
                                    token_pattern=r"[A-Za-z0-9]+")
        tfidf = self._vec.fit_transform(documents)
        # SVD needs fewer components than features/documents.
        n = max(2, min(self._components, min(tfidf.shape) - 1))
        self._svd = TruncatedSVD(n_components=n, random_state=0)
        reduced = self._svd.fit_transform(tfidf)
        self._docs = normalize(reduced)
        self.ready = True
        return self

    def similarities(self, query: str):
        """Cosine similarity of the query against every document (list[float])."""
        if not self.ready or not query.strip():
            return None
        q = normalize(self._svd.transform(self._vec.transform([query])))
        return (self._docs @ q.T).ravel().tolist()


def build_index(documents: list[str], components: int = 160) -> SemanticIndex:
    return SemanticIndex(components=components).fit(documents)
