#!/usr/bin/env python3
"""Live OpenRouter smoke — the exact production path the engine consumes.

1. key presence via env (never printed)
2. Gen-1 client directly: one real completion, print model + content preview
3. make_chat_fn adapter: the same request through the engine's contract

Runs one tiny prompt; costs a fraction of a cent (or $0 on :free models).
"""
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from redteam.config import LlmConfig                    # noqa: E402
from redteam.llm.openrouter import OpenRouterClient     # noqa: E402
from redteam.llm.planner import make_chat_fn            # noqa: E402


def main():
    if not os.environ.get("OPENROUTER_API_KEY"):
        print("FAIL: OPENROUTER_API_KEY not set")
        return 2
    cfg = LlmConfig()

    t0 = time.time()
    client = OpenRouterClient(cfg)
    result = client.chat(
        [{"role": "user",
          "content": "Reply with exactly one word: ALIVE"}],
        tools=None, role="plan")
    dt = time.time() - t0
    content = (result.message or {}).get("content") or ""
    print(f"[1] direct client  model={result.model}  {dt:.1f}s")
    print(f"    finish={result.finish_reason}  usage={result.usage}")
    print(f"    content={content[:80]!r}")

    chat_fn = make_chat_fn(cfg)
    assert chat_fn is not None, "adapter returned None despite key present"
    t0 = time.time()
    out = chat_fn([{"role": "user",
                    "content": "Reply with exactly one word: READY"}])
    dt = time.time() - t0
    print(f"[2] make_chat_fn    {dt:.1f}s  content={out[:80]!r}")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
