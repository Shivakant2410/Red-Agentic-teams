"""Engagement configuration: the signed Rules of Engagement (RoE), loaded and validated.

The engagement file is the contract for the whole run. Nothing in this system is
allowed to touch a target that is not described here. It also carries the runtime
config for the OpenRouter model router and the Kali sandbox. Keep the file under
version control alongside the signed authorization document, and never edit it
mid-run to widen scope without a new sign-off.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .objective import load_objective

if TYPE_CHECKING:  # imported lazily at runtime in _load_providers (avoids a cycle)
    from .llm.providers import ProviderConfig


class ConfigError(Exception):
    """Raised when the engagement file is missing required fields or is malformed."""


@dataclass(frozen=True)
class LlmConfig:
    """Model-router settings. Keys come from the environment, never the file.

    Two modes:
      - providers empty (default): Gen-1 single-provider OpenRouter routing, unchanged.
      - providers set: multi-provider gateway (see llm/gateway.py) — OpenAI, Anthropic,
        Z.ai, Ollama, Groq, vLLM, ... any OpenAI-compatible endpoint, role-routed and
        failover-ordered across the whole fleet.
    """

    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = "OPENROUTER_API_KEY"
    prefer_free: bool = True          # only route to $0 models
    require_tool_support: bool = True  # only models that advertise tool calling
    model_allow: tuple[str, ...] = ()  # if set, restrict rotation to these ids
    model_deny: tuple[str, ...] = ()   # never route to these ids
    max_rotations: int = 6             # how many models to try before giving up a turn
    # Pin a strong model to specific roles (e.g. {"plan": "openai/gpt-5.5", "poc": ...}).
    # Parsing/triage stay on the free pool; only reasoning pays. Free models remain the
    # fallback if the pinned model errors or rate-limits.
    # With providers set, a pin may also be "provider:model" (e.g. "anthropic:claude-sonnet-4-5").
    role_models: dict = field(default_factory=dict)
    temperature: float = 0.2
    max_tokens: int = 4096
    referer: str = "https://localhost/redteam-agent"  # OpenRouter attribution headers
    title: str = "redteam-agent"
    providers: tuple[ProviderConfig, ...] = ()


@dataclass(frozen=True)
class SandboxConfig:
    """Kali-in-Docker sandbox settings."""

    enable: bool = True
    image: str = "redteam-kali:latest"
    dockerfile: str = "redteam/sandbox/Dockerfile"
    network_name: str = "redteam-net"
    dns: tuple[str, ...] = ("1.1.1.1",)  # resolver reachable from inside the sandbox
    command_timeout: int = 300           # seconds per kali_exec
    container_name: str = "redteam-kali-run"
    memory: str = "2g"
    cpus: str = "2"


@dataclass(frozen=True)
class Engagement:
    """A validated, immutable view of the engagement's Rules of Engagement."""

    name: str
    client: str
    authorized_by: str
    ticket: str  # reference to the signed authorization (SOW, bug-bounty scope URL, etc.)
    starts: _dt.date
    ends: _dt.date

    # Scope
    allowed_hosts: tuple[str, ...]  # domains, wildcard domains (*.x.com), IPs, or CIDRs
    excluded_hosts: tuple[str, ...]  # explicit carve-outs that always win
    allowed_ports: tuple[int, ...]
    allowed_schemes: tuple[str, ...]

    # Safety limits
    max_requests_per_second: float
    max_total_requests: int
    allow_private_ranges: bool  # only true when the RoE explicitly covers internal ranges

    # Actions the agent may never take without a human pressing "yes" first.
    require_approval_for: tuple[str, ...]

    # Autonomy budgets (0 = unlimited). Wall-clock and total LLM tokens across the run.
    max_run_seconds: int = 0
    max_llm_tokens: int = 0

    # LLM strategist reflection between orchestrator rounds (see reflection.py). On by
    # default in multi-agent runs; costs one strong-role call per round.
    enable_reflection: bool = True

    # The crown jewel. When set, the run is judged by whether it was reached — not by how
    # many vulnerabilities were listed.
    objective: object = None      # Objective | None

    llm: LlmConfig = field(default_factory=LlmConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)

    raw: dict = field(default_factory=dict, repr=False)

    @property
    def is_active(self) -> bool:
        today = _dt.date.today()
        return self.starts <= today <= self.ends


def _require(data: dict, key: str) -> object:
    if key not in data or data[key] in (None, ""):
        raise ConfigError(f"engagement file is missing required field: {key!r}")
    return data[key]


def _as_date(value: object, field_name: str) -> _dt.date:
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value)
        except ValueError as exc:
            raise ConfigError(f"{field_name} must be an ISO date (YYYY-MM-DD): {exc}") from exc
    raise ConfigError(f"{field_name} must be a date")


def _load_providers(data: dict) -> tuple["ProviderConfig", ...]:
    """Parse llm.providers: a list of {kind, name?, base_url?, api_key_env?,
    models_allow?, models_deny?, prefer_free?, require_tool_support?, priority?}.
    `kind` accepts shortcuts (openrouter/openai/zai/ollama/groq/anthropic) that fill
    base_url + api_key_env, so a minimal entry is `{kind: anthropic}`."""
    from .llm.providers import ProviderConfig  # lazy: breaks config <-> llm cycle

    out: list[ProviderConfig] = []
    for entry in (data.get("providers") or []):
        if not isinstance(entry, dict):
            raise ConfigError("llm.providers entries must be mappings")
        out.append(ProviderConfig(
            name=str(entry.get("name", "") or ""),
            kind=str(entry.get("kind", "openai_compat") or "openai_compat"),
            base_url=str(entry.get("base_url", "") or ""),
            api_key_env=str(entry.get("api_key_env", "") or ""),
            models_allow=tuple(str(m) for m in (entry.get("models_allow") or ())),
            models_deny=tuple(str(m) for m in (entry.get("models_deny") or ())),
            prefer_free=(None if entry.get("prefer_free") is None else bool(entry.get("prefer_free"))),
            require_tool_support=(None if entry.get("require_tool_support") is None
                                  else bool(entry.get("require_tool_support"))),
            priority=int(entry.get("priority", 100)),
        ))
    return tuple(out)


def _load_llm(data: dict) -> LlmConfig:
    d = data.get("llm") or {}
    defaults = LlmConfig()
    return LlmConfig(
        base_url=str(d.get("base_url", defaults.base_url)),
        api_key_env=str(d.get("api_key_env", defaults.api_key_env)),
        prefer_free=bool(d.get("prefer_free", defaults.prefer_free)),
        require_tool_support=bool(d.get("require_tool_support", defaults.require_tool_support)),
        model_allow=tuple(str(m) for m in (d.get("model_allow") or ())),
        model_deny=tuple(str(m) for m in (d.get("model_deny") or ())),
        max_rotations=int(d.get("max_rotations", defaults.max_rotations)),
        role_models=dict(d.get("role_models") or {}),
        temperature=float(d.get("temperature", defaults.temperature)),
        max_tokens=int(d.get("max_tokens", defaults.max_tokens)),
        referer=str(d.get("referer", defaults.referer)),
        title=str(d.get("title", defaults.title)),
        providers=_load_providers(d),
    )


def _load_sandbox(data: dict) -> SandboxConfig:
    d = data.get("sandbox") or {}
    defaults = SandboxConfig()
    return SandboxConfig(
        enable=bool(d.get("enable", defaults.enable)),
        image=str(d.get("image", defaults.image)),
        dockerfile=str(d.get("dockerfile", defaults.dockerfile)),
        network_name=str(d.get("network_name", defaults.network_name)),
        dns=tuple(str(x) for x in (d.get("dns") or defaults.dns)),
        command_timeout=int(d.get("command_timeout", defaults.command_timeout)),
        container_name=str(d.get("container_name", defaults.container_name)),
        memory=str(d.get("memory", defaults.memory)),
        cpus=str(d.get("cpus", defaults.cpus)),
    )


def load_engagement(path: str | Path) -> Engagement:
    """Load, validate, and freeze the engagement file.

    Raises ConfigError on any problem. A malformed RoE must stop the run — we would
    rather fail closed than operate under an ambiguous scope.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"engagement file not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError("engagement file must be a YAML mapping")

    scope = data.get("scope") or {}
    limits = data.get("limits") or {}

    allowed_hosts = tuple(str(h).strip() for h in (scope.get("allowed_hosts") or []) if str(h).strip())
    if not allowed_hosts:
        raise ConfigError("scope.allowed_hosts must list at least one target")

    starts = _as_date(_require(data, "starts"), "starts")
    ends = _as_date(_require(data, "ends"), "ends")
    if ends < starts:
        raise ConfigError("engagement 'ends' is before 'starts'")

    return Engagement(
        name=str(_require(data, "name")),
        client=str(_require(data, "client")),
        authorized_by=str(_require(data, "authorized_by")),
        ticket=str(_require(data, "ticket")),
        starts=starts,
        ends=ends,
        allowed_hosts=allowed_hosts,
        excluded_hosts=tuple(str(h).strip() for h in (scope.get("excluded_hosts") or []) if str(h).strip()),
        allowed_ports=tuple(int(p) for p in (scope.get("allowed_ports") or [80, 443])),
        allowed_schemes=tuple(str(s).lower() for s in (scope.get("allowed_schemes") or ["http", "https"])),
        max_requests_per_second=float(limits.get("max_requests_per_second", 3.0)),
        max_total_requests=int(limits.get("max_total_requests", 2000)),
        allow_private_ranges=bool(scope.get("allow_private_ranges", False)),
        require_approval_for=tuple(
            str(a) for a in (data.get("require_approval_for") or ["destructive_command", "auth_bypass_attempt"])
        ),
        max_run_seconds=int(limits.get("max_run_seconds", 0)),
        max_llm_tokens=int(limits.get("max_llm_tokens", 0)),
        enable_reflection=bool(limits.get("enable_reflection", True)),
        objective=load_objective(data.get("objective")),
        llm=_load_llm(data),
        sandbox=_load_sandbox(data),
        raw=data,
    )
