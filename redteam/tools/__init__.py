"""Tool layer.

A ToolContext bundles every guardrail (scope, rate limit, audit, findings, approval)
plus the two execution surfaces — the Kali sandbox and the Playwright browser — and is
threaded into each tool call.

Each tool exposes:
  - a tool schema (name, description, input_schema) via `schema()`
  - a `run(ctx, **kwargs) -> str` handler returning a string result for the model
"""

from __future__ import annotations

import contextvars
import os
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from ..audit import AuditLog
from ..findings import FindingStore
from ..ratelimit import RateLimiter
from ..scope import ScopeGuard


# Identity of the specialist currently executing a tool call — set by
# agent._dispatch around every dispatch, read by search_peer_traces for
# self-exclusion ("search the OTHER workers, not me"). ContextVar because a
# swarm is N specialists in N threads: each thread resolves its own value.
current_agent: contextvars.ContextVar[str] = contextvars.ContextVar("current_agent", default="")


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
    # RECON V2: the run's shared evidence workspace (observation store +
    # traffic query/annotate layer). None keeps legacy behavior (tools that
    # need it degrade to an honest "not available" message).
    evidence_store: Optional[object] = None   # EvidenceStore | None
    workspace: Optional[object] = None        # EvidenceWorkspace | None
    # Phase B3: the run's detection BeliefFilter (sandbox/detection_belief.py) —
    # fed by tools/http.py's observation hook at every response return point and
    # read by the orchestrator's DriftPlusPenaltyScheduler to throttle the swarm.
    # None keeps the zero-overhead behavior (single-agent mode, legacy paths).
    detection: Optional[object] = None # BeliefFilter | None
    # RECON evidence plane: provenance + validation lifecycle for every recon
    # observation (mirrored into the graph). None = legacy paths (no log).
    observations: Optional[object] = None  # ObservationLog | None
    # Intercepting evidence proxy handle (EvidenceProxy | None): lets the
    # RECON-facing proxy_* tools query listener state and captured history.
    proxy: Optional[object] = None     # EvidenceProxy | None


class Tool(Protocol):
    name: str

    def schema(self) -> dict: ...
    def run(self, ctx: ToolContext, **kwargs) -> str: ...


def build_registry(enable_sandbox: bool = True, enable_browser: bool = True) -> dict[str, Tool]:
    """Instantiate the tool set. Import here to avoid circular imports."""
    from .access_tools import ClaimObjectiveTool, RecordAccessTool
    from .authsession import AuthenticateTool, SetSessionTool
    from .browser import (BrowserClickTool, BrowserContentTool, BrowserConsoleTool,
                          BrowserFillTool, BrowserInspectRequestTool,
                          BrowserNavigateTool, BrowserRequestsTool,
                          BrowserScreenshotTool)
    from .confirm import ConfirmFindingTool
    from .independent_verify import VerifyFindingIndependentlyTool
    from .jwt import JwtInspectTool
    from .kali import KaliExecTool
    from .logic import VerifyWorkflowAbuseTool
    from .nuclei import NucleiScanTool
    from .peer_traces import SearchPeerTracesTool
    from .probe import HttpProbeTool
    from .provision import ToolProvisionTool
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
    # The on-requirement toolbox: downloads a catalog tool when the agent needs
    # it (image layer with a sandbox, project venv without) — provisioning
    # places binaries only; execution stays under RoE via the other tools.
    tools.append(ToolProvisionTool())
    # Phase W1 discovery (docs/tool-integration-plan.md): ffuf/katana/arjun as
    # structured, rate-capped LEAD generators — endpoints fold into the graph,
    # parameters ride lead payloads into verify hints. None record findings.
    from .webdiscover import ContentDiscoveryTool, CrawlTool, ParamDiscoveryTool
    tools += [ContentDiscoveryTool(), CrawlTool(), ParamDiscoveryTool()]
    # Phase W1b deep probes (httpx/nmap): content-level host probing and service
    # fingerprinting of ONE allowed host each — HOST/SERVICE/TECHNOLOGY nodes the
    # planner, bandit buckets, and priors already read. Leads, never findings.
    from .hostprobe import HostProbeTool, PortScanTool
    tools += [HostProbeTool(), PortScanTool()]
    # Phase W2 first inspectors (the jwt_inspect pattern, first-party HTTP): the
    # inspect -> spec -> prove chain. xss_reflect_probe maps marker reflections to
    # sink contexts and emits a READY check_spec verify_vulnerability consumes 1:1;
    # graphql_inspect runs the deterministic 4-request checklist. Leads, never
    # findings; markers are benign (mapping, not payload blasting).
    from .webinspect import GraphqlInspectTool, XssReflectProbeTool
    tools += [XssReflectProbeTool(), GraphqlInspectTool()]
    # crosscheck_lead — the "never believe a tool's direct output" rule made
    # operational: every lead class carries a SECOND-METHOD entry (first-party HTTP /
    # raw socket vs a sandbox binary; fresh markers vs the inspector's own), verdicts
    # corroborated/contradicted/unverifiable, still leads-only. Unknown (tool, claim)
    # pairs fail closed.
    from .crosscheck import CrossCheckTool
    tools.append(CrossCheckTool())
    # First-party technique playbooks (data/playbooks/, ships in-repo): the offline
    # research layer — agents look techniques up here BEFORE inventing or searching.
    from .playbooks import FindTechniquesTool
    tools.append(FindTechniquesTool())
    # search_peer_traces = the swarm's read side (ARTEX worker-trace exchange port):
    # keyword-search sibling specialists' raw process traces for observations that
    # never became findings. Read-only over this run's event log, costs no budget.
    tools.append(SearchPeerTracesTool())
    # RECON V2 evidence workspace (redteam/recon_v2/): the specialist's read
    # side over its OWN accumulated evidence — observations (provenance,
    # validation, scope) and the wire history (browser + proxy + tools land in
    # the same traffic.jsonl). replay_request re-issues a recorded request
    # THROUGH the shared scope/budget/traffic plane (approval-gated).
    from .recon_workspace import (AssetReadTool, EvidenceInspectTool,
                                  EvidenceSearchTool, ProxyHistoryQueryTool,
                                  ReplayRequestTool)
    tools += [EvidenceSearchTool(), EvidenceInspectTool(),
              ProxyHistoryQueryTool(), ReplayRequestTool(), AssetReadTool()]
    # Operator tools: track what we hold and what it unlocks; claim the objective.
    tools += [RecordAccessTool(), ClaimObjectiveTool()]
    # Post-exploitation: harvest -> use -> prove the privilege boundary moved.
    from .postex import ExtractSecretsTool, ProvePrivilegeTool, TryCredentialTool
    tools += [ExtractSecretsTool(), TryCredentialTool(), ProvePrivilegeTool()]
    if enable_sandbox:
        tools.append(KaliExecTool())
    if enable_browser:
        tools += [BrowserNavigateTool(), BrowserContentTool(), BrowserClickTool(),
                  BrowserFillTool(), BrowserScreenshotTool(),
                  BrowserRequestsTool(), BrowserInspectRequestTool(),
                  BrowserConsoleTool()]
    # RECON evidence-plane readers: proxy history/status (queryable DURING the
    # run) and the observation log (provenance + validation states). The proxy
    # tools degrade honestly when no proxy runs in this run.
    from .proxytools import (ProxyFilterTool, ProxyHistoryTool, ProxyInspectTool,
                             ProxyReplayTool, ProxyStatusTool)
    tools += [ProxyStatusTool(), ProxyHistoryTool(), ProxyInspectTool(),
              ProxyFilterTool(), ProxyReplayTool()]
    from .passive import PassiveReconTool
    tools.append(PassiveReconTool())
    from .obsquery import ObservationsTool
    tools.append(ObservationsTool())
    tools += [RecordFindingTool(), RequestApprovalTool()]
    # Opt-in terminal plane for dockerless hosts (see tools/local_exec.py): NEVER
    # registered by default — the operator sets RED_LOCAL_EXEC=1 and accepts that
    # commands run on this host with no container confinement. Also DISTRACTS web
    # agents (observed: raw-socket HTTP via shell instead of http_probe) — enable
    # per run, not globally.
    if os.environ.get("RED_LOCAL_EXEC") == "1":
        from .local_exec import LocalExecTool
        tools.append(LocalExecTool())
    return {t.name: t for t in tools}
