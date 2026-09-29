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


class Tool(Protocol):
    name: str

    def schema(self) -> dict: ...
    def run(self, ctx: ToolContext, **kwargs) -> str: ...


def build_registry(enable_sandbox: bool = True, enable_browser: bool = True) -> dict[str, Tool]:
    """Instantiate the tool set. Import here to avoid circular imports."""
    from .access_tools import ClaimObjectiveTool, RecordAccessTool
    from .authsession import AuthenticateTool
    from .browser import (BrowserClickTool, BrowserContentTool, BrowserFillTool,
                          BrowserNavigateTool, BrowserScreenshotTool)
    from .confirm import ConfirmFindingTool
    from .kali import KaliExecTool
    from .skill_tools import ApplySkillTool
    from .template_search import ApplyTemplateTool, FindAttackTemplatesTool
    from .verify_tool import VerifyVulnerabilityTool
    from .workflow import RecordFindingTool, RequestApprovalTool

    tools: list[Tool] = []
    tools.append(ConfirmFindingTool())       # simple single/differential HTTP proofs
    # authenticate to hold identities; verify_vulnerability = the general agent-designed
    # proof primitive; apply_skill = re-run a PROVEN proof instead of designing a new one;
    # find/apply_template = research the corpus on demand instead of memorizing it.
    tools += [AuthenticateTool(), VerifyVulnerabilityTool(), ApplySkillTool(),
              FindAttackTemplatesTool(), ApplyTemplateTool()]
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
