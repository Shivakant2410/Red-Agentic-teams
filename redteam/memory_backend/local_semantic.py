"""LocalSemanticBackend — semantic memory with zero infrastructure.

The Helix path (helix_backend.py) gives real vector recall but needs Docker and a
downloaded model. This backend removes BOTH dependencies:

  - persistence: one JSON file (lessons + app-patterns + their embeddings)
  - embeddings: the on-device sentence-transformer when it is importable, else a
    built-in hashing embedder (token + char-trigram features, deterministic, no
    download, no model) — a lexical-semantic proxy that still catches stems,
    morphological variants, and near-phrases that exact tag matching misses.

Implements the same additive protocol HelixBackend does (load/save + the optional
semantic_recall_lessons / learn_pattern / recall_patterns), so ExperienceStore and
run.execute_run treat them interchangeably. Degrades gracefully: if the embedder
fails at runtime, semantic recall returns [] and the store behaves exactly like the
plain JSON backend — additive capability, never load-bearing.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from pathlib import Path

EMBEDDING_DIM = 512
_WORD = re.compile(r"[a-z0-9]+")
# Function words appear in every sentence and would dominate a bag-of-features
# vector; dropping them (and their trigrams) is what keeps unrelated texts near-orthogonal.
_STOP = frozenset("""the a an and or of to in on for with is are was were be been it its
this that as at by from we you your our not no""".split())


def _features(text: str) -> list[str]:
    """Content-word + character-trigram features (lowercased, stopwords dropped,
    sublinear term weight). The char trigrams make the vector robust to inflection
    and small typos: 'authbypass' and 'auth_bypass' share most of their trigrams."""
    text = (text or "").lower()
    words = [w for w in _WORD.findall(text) if w not in _STOP]
    counts: dict[str, float] = {}
    for w in words:
        counts[f"w:{w}"] = counts.get(f"w:{w}", 0.0) + 1.0
        padded = f"^{w}$"
        for i in range(max(len(padded) - 2, 1)):
            tri = f"c:{padded[i:i + 3]}"
            counts[tri] = counts.get(tri, 0.0) + 1.0
    return [(f, 1.0 + math.log(c)) for f, c in counts.items()]


def _bucket(feature: str) -> int:
    # blake2b is stable across processes/platforms (hash() is not: PYTHONHASHSEED).
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    return struct.unpack("<Q", digest)[0] % EMBEDDING_DIM


class HashingEmbedder:
    """Deterministic, dependency-free text vector. Not deep semantics — a robust
    lexical-overlap surrogate that needs no model, no download, and no network."""

    dim = EMBEDDING_DIM

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * EMBEDDING_DIM
        for feature, weight in _features(text):
            vec[_bucket(feature)] += weight
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def embed_many(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


def _best_available_embedder():
    """Real on-device transformer if it is importable AND its model loads; otherwise
    the hashing embedder. Never raises."""
    try:
        from .embedder import Embedder  # lazy: only costs anything when it exists
        emb = Embedder()
        emb.embed("warmup")  # force the model load now, not mid-run
        return emb
    except Exception:
        return HashingEmbedder()


def _cosine(a: list[float] | None, b: list[float] | None) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))  # vectors are stored normalized


class LocalSemanticBackend:
    """ExperienceStore backend: JSON persistence + cosine recall over stored vectors."""

    def __init__(self, path: str | Path, embedder=None):
        self._path = Path(path)
        self._embedder = embedder or _best_available_embedder()
        data = self._read()
        self._lessons: list[dict] = data.get("lessons", [])
        self._patterns: list[dict] = data.get("patterns", [])

    # -- persistence ------------------------------------------------------------

    def _read(self) -> dict:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"lessons": self._lessons, "patterns": self._patterns},
                                  ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path)

    # -- memory.Backend protocol (Lesson rows) -----------------------------------

    def load(self) -> list[dict]:
        rows = []
        for row in self._lessons:
            row = dict(row)
            row.pop("embedding", None)  # internal column; Lesson(**row) would choke
            row["tags"] = list(row.get("tags") or [])
            rows.append(row)
        return rows

    def save(self, rows: list[dict]) -> None:
        """Full replace (ExperienceStore's contract). Re-embeds rows that are new or
        changed (text changed / missing embedding / different dim)."""
        by_text = {r.get("text", ""): r for r in self._lessons}
        want_dim = getattr(self._embedder, "dim", EMBEDDING_DIM)
        fresh: list[dict] = []
        for row in rows:
            row = dict(row)
            text = row.get("text", "")
            old = by_text.get(text)
            emb = old.get("embedding") if old else None
            if emb is None or len(emb) != want_dim:
                emb = self._safe_embed(text)
            row["embedding"] = emb
            fresh.append(row)
        self._lessons = fresh
        self._write()

    # -- semantic recall (the additive capability) --------------------------------

    def semantic_recall_lessons(self, query: str, k: int = 3) -> list[dict]:
        qv = self._safe_embed(query)
        if qv is None:
            return []
        scored = sorted(
            (( _cosine(qv, l.get("embedding")), l) for l in self._lessons),
            key=lambda pair: pair[0], reverse=True)
        out = []
        for score, l in scored[:max(k, 0)]:
            if score < 0.15:  # noise floor: unrelated lessons shouldn't surface
                break
            out.append({"text": l.get("text", ""), "kind": l.get("kind", "?"),
                        "tags": list(l.get("tags") or []), "id": l.get("id", ""),
                        "score": round(score, 3)})
        return out

    def learn_pattern(self, description: str, tags: list[str] | None = None) -> None:
        if any(p.get("description") == description for p in self._patterns):
            return
        self._patterns.append({"description": description, "tags": list(tags or []),
                               "embedding": self._safe_embed(description)})
        self._write()

    def recall_patterns(self, query: str, k: int = 3) -> list[dict]:
        qv = self._safe_embed(query)
        if qv is None:
            return []
        scored = sorted(
            ((_cosine(qv, p.get("embedding")), p) for p in self._patterns),
            key=lambda pair: pair[0], reverse=True)
        out = []
        for score, p in scored[:max(k, 0)]:
            if score < 0.15:
                break
            out.append({"description": p.get("description", ""),
                        "tags": list(p.get("tags") or []), "score": round(score, 3)})
        return out

    # -- internals ------------------------------------------------------------

    def _safe_embed(self, text: str) -> list[float] | None:
        try:
            return list(self._embedder.embed(text))
        except Exception:
            return None  # degrade to plain-JSON behavior, never break a run
