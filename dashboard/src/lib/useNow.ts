"use client";

import { useEffect, useState } from "react";

/**
 * Ticking wall-clock (ms epoch). Returns null until mounted so that
 * SSR/prerender output never contains time-dependent strings
 * (prevents hydration mismatches on static export).
 */
export function useNow(intervalMs = 1000): number | null {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const iv = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(iv);
  }, [intervalMs]);
  return now;
}
