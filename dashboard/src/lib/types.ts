/**
 * Types mirroring the BINDING API contract (see /home/z/my-project/worklog.md).
 * Server: FastAPI at http://localhost:8000 (or same origin in production).
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

export interface LaunchRequest {
  engagement_path: string;
  objective: string;
  multi_agent?: boolean;
  max_steps?: number;
  source_dir?: string;
  yes_to_all?: boolean;
}

export interface LaunchResponse {
  run_id: string;
  out_dir: string;
  status: string;
  [k: string]: unknown;
}
