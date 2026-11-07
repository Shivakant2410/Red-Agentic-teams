# AI RAG & Vector-Store Abuse (LLM08/LLM04)

**CWE-1427** · 4 skill(s) · folder `categories/ai_rag_vector/`

## Skills in this shelf

- `ai/RAG document poisoning retrieval` (CWE-1427)
- `ai/Cross-context retrieval bleed` (CWE-863)
- `ai/Embedding semantic collision pull` (CWE-200)
- `ai/Corpus index mismatch stale source` (CWE-200)

## Technique

Retrieval-layer attacks: poisoned corpus chunks that win retrieval and get asserted with policy confidence, cross-TENANT retrieval bleed (authz at ingest but not at query), embedding semantic collisions that pull restricted documents, and index/corpus version mismatch serving stale truth.

## Proof design (why it is falsifiable)

Retrieval differentials: poisoned-vs-clean corpus, foreign-tenant canary in the answer, collision-phrase query vs innocuous twin, stale-source citation markers pinned by regex.

## Bypass variants / escalation ("think more beats level")

- Embedding-inversion attempts (reconstruct text from vectors)
- Distance-based enumeration (query shaping to walk the store)
- Multi-hop poisoning: planted doc cites another planted doc
- Chunk-overlap boundary abuse (sensitive data split across chunks)
- Metadata-filter bypass (tenant tag stripped by crafted query)

## Sources (copied & rewritten into our proof-first DSL)

- OWASP LLM Top 10 2025 — LLM08 vector/embedding weaknesses, LLM04 poisoning
- promptfoo red-team plugins — rag-poisoning
- published RAG-tenant-isolation research (cross-context bleed)

## False positives to rule out

Generic top-k noise — the tenant canary and poisoned-marker regexes exist because retrieval alone proves nothing.
