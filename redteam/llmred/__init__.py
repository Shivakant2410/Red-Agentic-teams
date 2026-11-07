"""llmred — a separate module for red-teaming LLMs (LLMs as TARGETS).

Two "LLM modules" live in this package on purpose, and confusing them would be a
design bug:

  - `redteam/llm/`     is the agent's own BRAIN (OpenRouter rotation, the Gen-2
                       gateway, role routing). It answers "which model thinks
                       for us".
  - `redteam/llmred/`  (this package) attacks LLM endpoints as TARGETS. It answers
                       "what can a motivated attacker make an LLM system do".

Why a separate module instead of another tool in `tools/`: a web-target tool run
rides on the sandbox firewall for scope enforcement. An LLM endpoint is not an
IP/CIDR target — the egress firewall would happily let the traffic out, so the
protections that make `redteam/` safe simply do not apply. llmred therefore
enforces its own fail-closed controls at the application layer: an explicit host
allowlist checked before every HTTP call, an authorization block (authorized_by +
ticket) without which the campaign refuses to start, a token-bucket rate limit
and a hard request budget reused from `ratelimit.py`, and a hash-chained trail
via `audit.py`.

Architecture (deliberately recognizable — each piece maps to prior art we studied,
full teardown in docs/competitor-landscape.md §AI-red-teaming-vendors):

  targets.py      PyRIT Targets / Lakera Red "Targets": stateless OpenAI-compatible
                  and stateful (session-id) endpoints, a scripted in-process
                  target for offline tests, and the agentic adapter
                  (AgenticLoopTarget) that wraps a REAL tool-calling loop and
                  records actual tool invocations so verdicts can measure what
                  an agent DID, not what it said. Host allowlist enforced per call.
  objectives.py   promptfoo "plugins" / Lakera "objectives": the probe pack, each
                  objective mapped to the OWASP LLM Top 10 2026 numbering used by
                  the paper (Red-Teaming AI Systems in the Agentic Era, sec. 3).
  strategies.py   promptfoo "strategies" / PyRIT converters: encoding transforms,
                  multilingual wrappers, plant-then-ask and cross-session turn
                  flows, a static escalation ladder (multishot), and a PAIR-style
                  adaptive loop (pair-lite) behind an optional attacker LLM port.
  detectors.py    PyRIT scorers, filtered through this repo's falsify discipline:
                  deterministic verdicts only, with UNDETERMINED as a first-class
                  outcome ("undetermined" is not "false" — PyRIT's rule, and the
                  honest answer most of the time). Action evidence (evaluate_tool_trace)
                  outranks text: an observed tool invocation is a leak even when
                  the reply refuses, and a compliance token without the matching
                  invocation is UNDETERMINED on an agent target.
  campaign.py     PyRIT scenarios + our own statistics layer: runs the
                  objective x strategy matrix under a hard budget, allocates each
                  attempt with the Thompson-sampling bandit from `bandit.py`
                  (cost-aware: multi-turn strategies pay their real turn cost),
                  rate-limits every HTTP call, and writes campaign.jsonl +
                  summary.json with Wilson intervals from `stats.py`.
  regression.py   The one Pillar-documented capability most vendors skip:
                  version-aware posture. Compares consecutive summaries and
                  labels every objective stable / new / hardened / regressed,
                  with a CI exit code so a regression fails the build.
  report.py       Markdown report: ASRs with intervals, framework mapping,
                  regression labels, evidence pointers.

Stats contract (matches stats.py and paper sec. 7): a reported ASR is
successes/decided with a Wilson interval — UNDETERMINED attempts and transport
errors are reported, never laundered into either success or failure.
"""

from __future__ import annotations

from .detectors import Verdict, evaluate, evaluate_tool_trace
from .objectives import PROBE_PACK, Objective, ToolCondition, select_objectives
from .regression import diff_summaries, gate_exit_code
from .report import render_markdown
from .strategies import TRANSFORMS, Strategy, encode, select_strategies
from .targets import (
    AgenticLoopTarget,
    AgentHarness,
    AgentRun,
    OpenAIToolLoop,
    ScriptedTarget,
    TargetAuthError,
    TargetConfig,
    TargetError,
    TargetRateLimited,
    ToolInvocation,
    target_from_config,
)

__all__ = [
    "PROBE_PACK",
    "AgenticLoopTarget",
    "AgentHarness",
    "AgentRun",
    "Objective",
    "OpenAIToolLoop",
    "ScriptedTarget",
    "Strategy",
    "TargetAuthError",
    "TargetConfig",
    "TargetError",
    "TargetRateLimited",
    "ToolCondition",
    "ToolInvocation",
    "TRANSFORMS",
    "Verdict",
    "diff_summaries",
    "encode",
    "evaluate",
    "evaluate_tool_trace",
    "gate_exit_code",
    "render_markdown",
    "select_objectives",
    "select_strategies",
    "target_from_config",
]
