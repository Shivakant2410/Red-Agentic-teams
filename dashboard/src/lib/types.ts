/**
 * Types mirroring the server's actual request/response models (redteam/server.py
 * is the source of truth). Server: FastAPI at http://localhost:8000 (or same
 * origin in production).
 * All payloads are parsed defensively: unknown fields are tolerated via index
 * signatures so a slightly-chatty server never crashes the UI.
 */

export type RunStatus = string; // running | completed | halted | error
export type Role = string; // recon | exploit | access | logic | verify | single | orchestrator
export type Severity = string; // critical | high | medium | low | info

export interface Health {
  status: string;
  version: string;
  runs_root: string;
  [k: string]: unknown;
}

export interface RunSummary {
  run_id: string;
  name: string;
  objective: string;
  status: RunStatus;
  started: string;
  updated: string;
  steps: number;
  findings: number;
  tokens: number;
  [k: string]: unknown;
}

export interface Finding {
  id?: string;
  title: string;
  severity: Severity;
  confidence?: string;
  description?: string;
  proof?: string;
  evidence?: unknown;
  [k: string]: unknown;
}

export interface ObjectiveCriterion {
  id: string;
  description: string;
  achieved: boolean;
  evidence?: string;
  [k: string]: unknown;
}

export interface ObjectiveState {
  description: string;
  criteria: ObjectiveCriterion[];
  achieved: boolean;
  done: number;
  total: number;
  [k: string]: unknown;
}

export interface KillChainStage {
  stage: string;
  achieved: boolean;
  since?: string;
  [k: string]: unknown;
}

export interface Reflection {
  ts: string;
  assessment: string;
  adjustments?: string;
  focus_next?: string[];
  [k: string]: unknown;
}

export interface RunManifest {
  objective: string;
  engagement: string;
  status: RunStatus;
  steps: number;
  findings: number;
  tokens: number;
  halt_reason?: string;
  started?: string;
  updated?: string;
  [k: string]: unknown;
}

export interface RunDetail {
  run_id: string;
  status: RunStatus;
  /** "classic" (single agent / orchestrator swarm) or "mission" (coordination core). */
  driver?: string;
  manifest: RunManifest;
  findings: Finding[];
  objective?: ObjectiveState;
  killchain?: KillChainStage[];
  graph?: {
    nodes?: unknown;
    endpoints?: unknown;
    params?: unknown;
    hosts?: unknown;
  };
  attack_tree?: {
    todo?: unknown[];
    in_progress?: unknown[];
    failed?: unknown[];
    completed?: unknown[];
  };
  reflections?: Reflection[];
  [k: string]: unknown;
}

/**
 * Event union per contract catalog:
 *   run.start {objective, engagement, mode}
 *   phase.change {phase, round}
 *   agent.turn {role, step, model, content}
 *   tool.call {role, step, tool, args}
 *   tool.result {role, step, tool, ok, preview}
 *   finding.recorded {id, title, severity, confidence}
 *   finding.confirmed {id, title, severity}
 *   objective.progress {done, total}
 *   approval.requested {id, action, details}
 *   approval.resolved {id, approved}
 *   swarm.claim {worker, technique, target}
 *   reflection {assessment, adjustments, focus_next}
 *   llm.rotate {model, reason}
 *   run.finish {status, findings, tokens, halt_reason}
 * role ∈ recon|exploit|access|logic|verify|single|orchestrator
 */
export interface RunEvent {
  seq: number;
  ts: string;
  run_id: string;
  type: string;
  // run.*
  objective?: string;
  engagement?: string;
  mode?: string;
  status?: RunStatus;
  findings?: number;
  tokens?: number;
  halt_reason?: string;
  // phase.change
  phase?: string;
  round?: number;
  // agent.turn / tool.*
  role?: Role;
  step?: number;
  model?: string;
  content?: string;
  tool?: string;
  args?: unknown;
  ok?: boolean;
  preview?: string;
  // findings
  id?: string;
  title?: string;
  severity?: Severity;
  confidence?: string;
  // objective.progress
  done?: number;
  total?: number;
  // approvals
  action?: string;
  details?: string;
  approved?: boolean;
  // swarm.claim
  worker?: string;
  technique?: string;
  target?: string;
  // reflection
  assessment?: string;
  adjustments?: string;
  focus_next?: string[];
  // llm.rotate
  reason?: string;

  [k: string]: unknown;
}

export interface EventsPage {
  events: RunEvent[];
  next_cursor: number;
  [k: string]: unknown;
}

export interface PendingApproval {
  id: string;
  action: string;
  details?: string;
  ts?: string;
  [k: string]: unknown;
}

export interface LlmOverride {
  /** Provider kind the engine understands: openai | zai | gemini | openrouter |
   *  ollama | groq | anthropic — or any kind + base_url (openai_compat escape hatch). */
  provider: string;
  /** Empty = provider's natural rotation; a value pins llm.providers[].models_allow. */
  model?: string;
  /** Run-scoped credential: carried on THIS run's server-side options only
   *  (resolved into that run's provider sessions at construction). Never
   *  written to the process env, engagement YAML, manifests, events, or logs —
   *  concurrent runs with different keys cannot cross-use them. Omit to use
   *  preconfigured env credentials. */
  api_key?: string;
  /** Override the kind's default endpoint (vLLM, LM Studio, a private proxy, ...). */
  base_url?: string;
}

export interface LaunchRequest {
  engagement_path: string;
  objective: string;
  multi_agent?: boolean;
  max_steps?: number;
  source_dir?: string;
  yes_to_all?: boolean;
  /** Optional model/provider selection from the launch form; omit to use
   *  whatever the engagement file configures. */
  llm?: LlmOverride;
}

/** POST /api/llm/preflight — server-side launch preflight (agent server → LLM
 *  endpoint only; never the client's target). */
export interface LlmPreflightBody {
  provider: string;
  model?: string;
  base_url?: string;
  /** Held in memory for this single request; never echoed in the result. */
  api_key?: string;
}

export interface LlmPreflightCheck {
  check: string;
  ok: boolean;
  detail: string;
}

export interface LlmPreflightResult {
  provider: string;
  base_url: string;
  model: string;
  reachable: boolean;
  model_found: boolean;
  tool_call_ok: boolean;
  args_parsed: boolean;
  ok: boolean;
  latency_ms: number;
  error: string;
  checks: LlmPreflightCheck[];
}

/** GET /api/llm/models — real model ids served by the endpoint. */
export interface LlmModelsResponse {
  provider: string;
  base_url: string;
  models: string[];
}

/** POST /api/missions — adaptive mission launch (MissionBody server-side). */
export interface MissionLaunchRequest {
  engagement_path: string;
  objective: string;
  max_steps?: number;
  asset_feed?: string;
  yes_to_all?: boolean;
  /** Deliberately opt-in static task plan. Omit/empty (the default) = the
   *  dynamic AttackTree frontier plans and replans on its own. */
  plan?: MissionPlanTask[];
  /** Same provider/model selection contract as LaunchRequest.llm. */
  llm?: LlmOverride;
}

export interface MissionPlanTask {
  id?: string;
  technique?: string;
  target?: string;
  objective?: string;
  depends_on?: string[];
  [k: string]: unknown;
}

/** Both launch endpoints mint one id; mission identity and run identity stay
 *  separate logical fields (mission_id == run_id today, 1:N-capable later). */
export interface MissionLaunchResponse {
  mission_id: string;
  run_id: string;
  run_ids: string[];
  engagement: string;
  out_dir: string;
  status: string;
  driver: string;
  [k: string]: unknown;
}

export interface MissionTask {
  id?: string;
  technique?: string;
  target?: string;
  objective?: string;
  status?: string;
  specialist?: string;
  attempts?: number;
  [k: string]: unknown;
}

export interface MissionSummary {
  mission_id: string;
  run_id: string;
  run_ids: string[];
  engagement: string;
  ticket?: string;
  objective: string;
  status: string;
  created: string;
  updated: string;
  tasks: number;
  [k: string]: unknown;
}

export interface MissionDetail {
  mission_id: string;
  run_id: string;
  run_ids: string[];
  engagement: string;
  ticket?: string;
  objective: string;
  status: string;
  halt_reason?: string;
  tasks: MissionTask[];
  recent_events: RunEvent[];
  [k: string]: unknown;
}

export interface LaunchResponse {
  run_id: string;
  out_dir: string;
  status: string;
  [k: string]: unknown;
}

export interface BenchCard {
  run_id: string;
  ts: string;
  arm: string;
  target_key: string;
  target: string;
  objective_achieved: boolean;
  completion: number;
  confirmed: number;
  precision: number;
  recall: number;
  f1: number;
  steps: number;
  actions: number;
  tokens: number;
  elapsed_s: number;
  halt_reason: string;
}

export interface BenchBoard {
  runs: BenchCard[];
  arms: string[];
  achieved: number;
  confirmed: number;
  total: number;
}
