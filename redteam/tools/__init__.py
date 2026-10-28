"""Tool layer.

A ToolContext bundles every guardrail (scope, rate limit, audit, findings, approval)
plus the two execution surfaces — the Kali sandbox and the Playwright browser — and is
threaded into each tool call.

Each tool exposes:
  - a tool schema (name, description, input_schema) via `schema()`
  - a `run(ctx, **kwargs) -> str` handler returning a string result for the model
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from ..audit import AuditLog
from ..findings import FindingStore
from ..ratelimit import RateLimiter
from ..scope import ScopeGuard


@dataclass
class ToolContext:
    scope: ScopeGuard
    limiter: RateLimiter
    audit: AuditLog
    findings: FindingStore
    # Returns True to approve an action, False to deny. Default is deny (fail closed).
    approve: Callable[[str, dict], bool]
    sandbox: Optional[object] = None   # KaliSandbox | None
    browser: Optional[object] = None   # BrowserController | None
    graph: Optional[object] = None     # KnowledgeGraph | None (target surface)
    sessions: Optional[object] = None  # SessionStore | None
    skills: Optional[object] = None    # SkillLibrary | None
    access: Optional[object] = None    # AccessGraph | None (what WE hold)
    objective: Optional[object] = None # Objective | None (what winning means)
    killchain: Optional[object] = None # KillChain | None
    # Live telemetry bus (events.py) — None in legacy CLI mode (zero overhead), always
    # set for server/dashboard runs. Tools emit finding/approval events through it.
    events: Optional[object] = None    # EventBus | None
    # ARTEX-port telemetry: wire-evidence traffic log + asset inventory. None keeps
    # the Gen-1 zero-overhead behavior; run.py wires both for every new run.
    traffic: Optional[object] = None   # TrafficRecorder | None
    inventory: Optional[object] = None # AssetInventory | None


class Tool(Protocol):
    name: str

    def schema(self) -> dict: ...
    def run(self, ctx: ToolContext, **kwargs) -> str: ...


def build_registry(enable_sandbox: bool = True, enable_browser: bool = True) -> dict[str, Tool]:
    """Instantiate the tool set. Import here to avoid circular imports."""
    from .access_tools import ClaimObjectiveTool, RecordAccessTool
    from .authsession import AuthenticateTool, SetSessionTool
    from .browser import (BrowserClickTool, BrowserContentTool, BrowserFillTool,
                          BrowserNavigateTool, BrowserScreenshotTool)
    from .confirm import ConfirmFindingTool
    from .independent_verify import VerifyFindingIndependentlyTool
    from .jwt import JwtInspectTool
    from .kali import KaliExecTool
    from .logic import VerifyWorkflowAbuseTool
    from .nuclei import NucleiScanTool
    from .probe import HttpProbeTool
    from .skill_tools import ApplySkillTool
    from .spa_recon import SpaReconTool
    from .surface import SurfaceScanTool
    from .template_search import ApplyTemplateTool, FindAttackTemplatesTool
    from .verify_tool import VerifyVulnerabilityTool
    from .workflow import RecordFindingTool, RequestApprovalTool

    tools: list[Tool] = []
    tools.append(ConfirmFindingTool())       # simple single/differential HTTP proofs
    # authenticate to hold identities; set_session registers operator-handed static
    # tokens (assumed-breach material) as sessions; http_probe = cheap session-aware
    # LOOKING AROUND that never touches the finding pipeline;
    # verify_vulnerability = the general agent-designed proof primitive;
    # verify_workflow_abuse = the business-logic primitive (ordered sequences,
    # single-run + control — see tools/logic.py); apply_skill = re-run a PROVEN proof
    # instead of designing a new one; find/apply_template = research the corpus on
    # demand instead of memorizing it.
    # verify_finding_independently = the only tool that may promote a finding to
    # "confirmed" — meant to be called from a separate context (see orchestrator.VERIFY).
    tools += [AuthenticateTool(), SetSessionTool(), HttpProbeTool(),
              VerifyVulnerabilityTool(), VerifyWorkflowAbuseTool(),
              VerifyFindingIndependentlyTool(), ApplySkillTool(), FindAttackTemplatesTool(),
              ApplyTemplateTool()]
    # Signature reconnaissance: jwt_inspect is deterministic offline analysis; nuclei_scan
    # produces leads that must survive the proof pipeline; surface_scan fills the asset
    # inventory from the RoE allowlist itself (never widens scope); spa_recon walks a
    # login-gated SPA with bootstrap mocks (ARTEX api-recon port) to reveal the runtime
    # API surface. None record findings.
    tools += [JwtInspectTool(), NucleiScanTool(), SurfaceScanTool(), SpaReconTool()]
    # Operator tools: track what we hold and what it unlocks; claim the objective.
    tools += [RecordAccessTool(), ClaimObjectiveTool()]
    # Post-exploitation: harvest -> use -> prove the privilege boundary moved.
    from .postex import ExtractSecretsTool, ProvePrivilegeTool, TryCredentialTool
    tools += [ExtractSecretsTool(), TryCredentialTool(), ProvePrivilegeTool()]
    if enable_sandbox:
        tools.append(KaliExecTool())
    if enable_browser:
        tools += [BrowserNavigateTool(), BrowserContentTool(), BrowserClickTool(),
                  BrowserFillTool(), BrowserScreenshotTool()]
    tools += [RecordFindingTool(), RequestApprovalTool()]
    return {t.name: t for t in tools}
