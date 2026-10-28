/**
 * Tiny fetch wrapper around the binding API contract.
 * API base: process.env.NEXT_PUBLIC_API_BASE || "" (same origin — FastAPI
 * serves both the static dashboard and /api in production).
 */
import type {
  EventsPage,
  Health,
  LaunchRequest,
  LaunchResponse,
  PendingApproval,
  RunDetail,
  RunSummary,
} from "./types";

export const API_BASE: string = process.env.NEXT_PUBLIC_API_BASE || "";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function errMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return "request failed";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "cannot reach server");
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body: unknown = await res.json();
      if (
        body &&
        typeof body === "object" &&
        "detail" in body &&
        typeof (body as { detail: unknown }).detail === "string"
      ) {
        detail = (body as { detail: string }).detail;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  health: () => request<Health>("/api/health"),

  listRuns: () => request<{ runs: RunSummary[] }>("/api/runs"),

  getRun: (runId: string) =>
    request<RunDetail>(`/api/runs/${encodeURIComponent(runId)}`),

  getEvents: (runId: string, after: number) =>
    request<EventsPage>(
      `/api/runs/${encodeURIComponent(runId)}/events?after=${after}`,
    ),

  launchRun: (body: LaunchRequest) =>
    request<LaunchResponse>("/api/runs", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  stopRun: (runId: string) =>
    request<{ ok: boolean }>(`/api/runs/${encodeURIComponent(runId)}/stop`, {
      method: "POST",
      body: JSON.stringify({}),
    }),

  pendingApprovals: (runId: string) =>
    request<{ pending: PendingApproval[] }>(
      `/api/runs/${encodeURIComponent(runId)}/approvals`,
    ),

  resolveApproval: (approvalId: string, approve: boolean) =>
    request<{ ok: boolean }>(
      `/api/approvals/${encodeURIComponent(approvalId)}`,
      { method: "POST", body: JSON.stringify({ approve }) },
    ),
};

export function reportUrl(runId: string): string {
  return `${API_BASE}/api/runs/${encodeURIComponent(runId)}/report`;
}
