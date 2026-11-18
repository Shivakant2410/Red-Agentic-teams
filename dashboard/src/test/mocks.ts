/**
 * Shared test doubles for component tests. Self-contained (no imports from
 * the code under test): the api mock and the navigation mock are module-scoped
 * so `vi.mock("@/lib/api", async () => ({ api, ... }))` factories can hand the
 * SAME instance to both the component graph and the test file.
 */
import { vi } from "vitest";

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

export const reportUrl = (id: string): string => `/api/runs/${id}/report`;
export const API_BASE = "";

/** Loose contract on purpose: tests drive every method with their own payloads
 *  via mockResolvedValueOnce, and read back submitted bodies via mock.calls. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyAsync = (...args: any[]) => Promise<any>;

export const api = {
  health: vi.fn<AnyAsync>(async () => ({ status: "ok", version: "0.0.0", runs_root: "/tmp" })),
  listRuns: vi.fn<AnyAsync>(async () => ({ runs: [] })),
  getRun: vi.fn<AnyAsync>(async () => ({})),
  getEvents: vi.fn<AnyAsync>(async () => ({ events: [], next_cursor: 0 })),
  launchRun: vi.fn<AnyAsync>(async (body: Record<string, unknown>) => ({ run_id: "R1", status: "running", ...body })),
  launchMission: vi.fn<AnyAsync>(async (body: Record<string, unknown>) => ({
    mission_id: "R1", run_id: "R1", run_ids: ["R1"], status: "running", driver: "mission", ...body,
  })),
  listMissions: vi.fn<AnyAsync>(async () => ({ missions: [] })),
  getMission: vi.fn<AnyAsync>(async () => ({})),
  stopRun: vi.fn<AnyAsync>(async () => ({ ok: true })),
  pendingApprovals: vi.fn<AnyAsync>(async () => ({ pending: [] })),
  resolveApproval: vi.fn<AnyAsync>(async () => ({ ok: true })),
  bench: vi.fn<AnyAsync>(async () => ({ runs: [], arms: [], achieved: 0, confirmed: 0, total: 0 })),
};

export function clearApiMocks() {
  for (const fn of Object.values(api)) {
    if (typeof fn === "function" && "mockClear" in fn) {
      (fn as unknown as { mockClear: () => void }).mockClear();
    }
  }
}

/** Mutable handles for the navigation mock (search string + push spy). */
export const navState: { search: string; push: ReturnType<typeof vi.fn> | null } = {
  search: "",
  push: null,
};

export function makeNavigationMock() {
  const push = vi.fn();
  navState.push = push;
  return {
    useRouter: () => ({ push, replace: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
    useSearchParams: () => new URLSearchParams(navState.search),
    usePathname: () => "/",
    useParams: () => ({}),
  };
}

export function makeRunStreamStub() {
  return { events: [], connection: "polling" as const };
}
