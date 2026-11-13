"""redteam.pi — proof-first prompt-injection testing (OWASP LLM01).

The LLM01 capability inside this repo's architecture: versioned techniques
(families A-E) delivered as controlled simulated untrusted content against
the llm_app target, judged by four deterministic oracle primitives, decided
with earned-RESISTED verdicts, recorded as spec-conformant evidence, bridged
into the existing pending_verification -> independent-verify pipeline, and
measured with honest bench metrics.

Isolation contract: this package reuses llmred's TARGET machinery and the
repo's findings/stats/audit infrastructure, but its oracle/technique
abstractions import NOTHING from llmred — future OWASP categories can reuse
them by pointing their techniques at the same oracle layer.

Offline contract: everything here runs deterministically against fixture
apps (no network). Real-model targets ride llmred's OpenAIToolLoop harness;
live-model ASR runs are the operator's step, kept separate from fixture
numbers.
"""

from .oracles import (  # noqa: F401
    AttemptObservation,
    AuthzPolicy,
    CanaryStage,
    JudgeAudit,
    OracleResult,
    SafetyPredicate,
    SchemaFinding,
    ToolRule,
    ToolSchema,
    Verdict,
    annotate_with_judge,
    canary_hits,
    canary_in_args,
    combine_verdicts,
    evaluate_canary,
    evaluate_forbidden_tools,
    evaluate_predicates,
    evaluate_schema_authz_on,
    is_canary_shaped,
    make_canary,
    tag_decode,
    tag_encode,
    zw_embed,
    zw_strip,
)
from .evidence import EvidenceRecord, validate_record  # noqa: F401
from .techniques import (  # noqa: F401
    DELIVERY_CHANNELS,
    PITechnique,
    TECHNIQUES,
    attack_tree_entries,
    select_techniques,
    techniques_for_family,
)
from .app_target import (  # noqa: F401
    IOPolicy,
    LLMApp,
    LLMAppConfig,
    hardened_app,
    llm_app_target,
    vulnerable_app,
)
from .runner import PIEngagement, PIEngagementConfig  # noqa: F401
from .bench import bench_with_verification, compute_bench  # noqa: F401

__all__ = [
    "AttemptObservation", "AuthzPolicy", "CanaryStage", "JudgeAudit",
    "OracleResult", "SafetyPredicate", "SchemaFinding", "ToolRule",
    "ToolSchema", "Verdict", "annotate_with_judge", "canary_hits",
    "canary_in_args", "combine_verdicts", "evaluate_canary",
    "evaluate_forbidden_tools", "evaluate_predicates",
    "evaluate_schema_authz_on", "is_canary_shaped", "make_canary",
    "EvidenceRecord", "validate_record", "DELIVERY_CHANNELS", "PITechnique",
    "TECHNIQUES", "attack_tree_entries", "select_techniques",
    "techniques_for_family", "IOPolicy", "LLMApp", "LLMAppConfig",
    "hardened_app", "llm_app_target", "vulnerable_app", "PIEngagement",
    "PIEngagementConfig", "bench_with_verification", "compute_bench",
    "tag_decode", "tag_encode", "zw_embed", "zw_strip",
]
