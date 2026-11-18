import { renderHook, act } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { usePoll } from "./usePoll";

/** Phase 8: polling authority — cadence, error retention, cleanup. */
describe("usePoll", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("fetches immediately and exposes data", async () => {
    const fetcher = vi.fn(async () => ({ runs: [1] }));
    const { result } = renderHook(() => usePoll(fetcher, null, "k"));
    await act(async () => { await Promise.resolve(); });
    expect(result.current.data).toEqual({ runs: [1] });
    expect(result.current.error).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("keeps the last good data when a later poll fails", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce({ runs: ["first"] })
      .mockRejectedValueOnce(new Error("boom"));
    const { result } = renderHook(() => usePoll(fetcher, 5_000, "k"));
    await act(async () => { await Promise.resolve(); });
    expect(result.current.data).toEqual({ runs: ["first"] });
    await act(async () => { vi.advanceTimersByTime(5_000); await Promise.resolve(); });
    expect(result.current.error).toBe("boom");
    expect(result.current.data).toEqual({ runs: ["first"] });  // NOT blanked
  });

  it("re-creates the interval when the cadence changes (single interval)", async () => {
    const fetcher = vi.fn(async () => ({}));
    const { result, rerender, unmount } = renderHook(
      ({ ms }) => usePoll(fetcher, ms, "k"),
      { initialProps: { ms: 15_000 as number | null } },
    );
    await act(async () => { await Promise.resolve(); });
    expect(fetcher).toHaveBeenCalledTimes(1);
    rerender({ ms: 5_000 });
    await act(async () => { vi.advanceTimersByTime(5_000); await Promise.resolve(); });
    // exactly one more fetch for one 5s tick — no duplicated intervals
    expect(fetcher).toHaveBeenCalledTimes(2);
    await act(async () => { vi.advanceTimersByTime(5_000); await Promise.resolve(); });
    expect(fetcher).toHaveBeenCalledTimes(3);
    unmount();
    await act(async () => { vi.advanceTimersByTime(30_000); await Promise.resolve(); });
    expect(fetcher).toHaveBeenCalledTimes(3);                 // cleaned up
    expect(result.current.data).toBeDefined();
  });

  it("does not poll when intervalMs is null (fetch-once)", async () => {
    const fetcher = vi.fn(async () => ({}));
    renderHook(() => usePoll(fetcher, null, "k"));
    await act(async () => { await Promise.resolve(); });
    await act(async () => { vi.advanceTimersByTime(60_000); await Promise.resolve(); });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
