"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { errMessage } from "./api";

/**
 * Small polling hook with graceful failure: keeps the last good data on
 * error and exposes the error message instead. Never blanks the screen.
 */
export function usePoll<T>(
  fetcher: () => Promise<T>,
  intervalMs: number | null,
  watch?: string | null,
): { data: T | null; error: string | null; refresh: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fetcher);
  fnRef.current = fetcher;

  const refresh = useCallback(async () => {
    try {
      const d = await fnRef.current();
      setData(d);
      setError(null);
    } catch (e) {
      setError(errMessage(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    if (intervalMs == null) return;
    const iv = setInterval(() => void refresh(), intervalMs);
    return () => clearInterval(iv);
  }, [refresh, intervalMs, watch]);

  return { data, error, refresh };
}
