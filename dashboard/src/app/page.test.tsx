import { act, render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import RunsOverviewPage from "./page";
import { api, clearApiMocks, navState } from "@/test/mocks";

vi.mock("@/lib/api", async () => {
  const m = await import("@/test/mocks");
  return { api: m.api, errMessage: m.errMessage, ApiError: m.ApiError, reportUrl: m.reportUrl, API_BASE: m.API_BASE };
});
vi.mock("next/navigation", async () => {
  const m = await import("@/test/mocks");
  return m.makeNavigationMock();
});

const run = (id: string, status: string, findings = 0) => ({
  run_id: id, name: id, objective: `obj ${id}`, status,
  started: "2026-11-18T00:00:00Z", updated: "2026-11-18T00:00:00Z",
  steps: 1, findings, tokens: 5,
});

/** Phase 8: overview — ONE authoritative poll owns the table; cadence adapts
 *  (5s active / 15s idle); failures keep the last good list; a launched run
 *  (window event) refreshes immediately. All timing is driven with act() +
 *  fake-timer advancement (waitFor would race the fake clock). */
describe("runs overview", () => {
  beforeEach(() => {
    clearApiMocks();
    navState.search = "";
    vi.useFakeTimers({ shouldAdvanceTime: false });
  });
  afterEach(() => vi.useRealTimers());

  it("updates the table from the single polling state without refresh", async () => {
    api.listRuns
      .mockResolvedValueOnce({ runs: [run("r-1", "running")] })
      .mockResolvedValueOnce({ runs: [run("r-1", "running"), run("r-2", "completed", 3)] });
    render(<RunsOverviewPage />);
    await act(async () => {});                       // initial fetch + render
    expect(screen.getByText(/obj r-1/i)).toBeInTheDocument();
    expect(screen.queryByText(/obj r-2/i)).not.toBeInTheDocument();

    // active cadence tick (the 5s interval starts once data shows a run)
    await act(async () => { await vi.advanceTimersByTimeAsync(6_000); });
    expect(api.listRuns).toHaveBeenCalledTimes(2);
    expect(screen.getByText(/obj r-2/i)).toBeInTheDocument();
  });

  it("backs off to 15s when all runs are idle", async () => {
    api.listRuns
      .mockResolvedValueOnce({ runs: [run("r-1", "running")] })
      .mockResolvedValueOnce({ runs: [run("r-1", "completed")] });
    render(<RunsOverviewPage />);
    await act(async () => {});
    await act(async () => { await vi.advanceTimersByTimeAsync(6_000); });   // active tick
    expect(screen.getByText(/completed/i)).toBeInTheDocument();
    const callsAfterActive = api.listRuns.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });   // would tick at 5s
    expect(api.listRuns.mock.calls.length).toBe(callsAfterActive);          // backed off
    await act(async () => { await vi.advanceTimersByTimeAsync(11_000); });  // ticks at 15s
    expect(api.listRuns.mock.calls.length).toBe(callsAfterActive + 1);
  });

  it("keeps the last good run list when the feed fails", async () => {
    api.listRuns
      .mockResolvedValueOnce({ runs: [run("r-1", "completed")] })
      .mockRejectedValueOnce(new Error("feed down"));
    render(<RunsOverviewPage />);
    await act(async () => {});
    expect(screen.getByText(/obj r-1/i)).toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(16_000); });
    expect(screen.getByText(/runs feed unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/obj r-1/i)).toBeInTheDocument();       // NOT blanked
  });

  it("refreshes immediately when a run is launched (window event)", async () => {
    api.listRuns.mockResolvedValue({ runs: [] });
    render(<RunsOverviewPage />);
    await act(async () => {});
    expect(api.listRuns).toHaveBeenCalledTimes(1);
    await act(async () => { window.dispatchEvent(new Event("run:launched")); });
    expect(api.listRuns).toHaveBeenCalledTimes(2);
  });
});
