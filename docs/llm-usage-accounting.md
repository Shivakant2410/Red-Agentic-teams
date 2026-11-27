# LLM usage and USD cost accounting

Every provider attempt is reserved in a SQLite usage ledger before network I/O. Successful responses record prompt/completion tokens and cost; failed or unpriced attempts remain visible rather than being treated as zero-cost.

## Storage

- Default: each run writes `llm-usage.sqlite3` in its run directory.
- Shared operator ledger: set `REDTEAM_USAGE_DB=/path/to/usage.sqlite3` to use one inter-process-safe database across runs. Each record carries the run ID, while the daily request cap is shared across the database.
- `REDTEAM_LLM_DAILY_REQUEST_LIMIT` controls the request cap (default 1000 per database per UTC day).

The ledger stores provider/model IDs, phase, timestamps, token counts, response IDs, and cost metadata. It does not store prompts, completions, API keys, or target secrets.

## Cost semantics

1. Provider-reported USD cost is preferred when present (for example, OpenRouter usage metadata).
2. Otherwise, a provider's model catalog prompt/completion rates are multiplied by measured token counts.
3. If neither source exists, cost is unknown. The benchmark scorecard reports USD cost per confirmed objective as null whenever any request in the paired runs has unknown cost.

This avoids presenting a partial sum as total spend. Anthropic models without a returned cost or an available pricing catalog remain unknown until a trusted price source is integrated.

## Phase qualification

Phase-specific model qualification records are stored by `QualificationStore` in `redteam.llm.preflight`. The old `src/agentic_setup` modules are compatibility shims during the migration and are not separate implementations.
