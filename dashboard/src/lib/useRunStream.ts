"use client";

import { useEffect, useRef, useState } from "react";
import { API_BASE, api } from "./api";
import type { RunEvent } from "./types";

export type ConnectionState = "connecting" | "live" | "polling" | "ended";

const POLL_INTERVAL_MS = 2000; // fallback polling of /events
const SSE_RETRY_MS = 5000; // wait before retrying SSE after an error

/**
 * Live event stream for one run.
 *
 * Transport strategy (per contract):
 *  1. Primary: SSE on GET /api/runs/{id}/stream?after={cursor}
 *     - messages arrive as `event: run_event` with JSON payloads
 *     - `event: ping` heartbeats are ignored
 *  2. On SSE error: close, poll GET /api/runs/{id}/events?after={cursor}
 *     every 2s, and retry SSE after 5s. Cursor = last seen seq, so the
 *     handoff never duplicates or drops events.
 *  3. When a run.finish event lands (or the caller reports the run ended),
 *     tear everything down and mark the connection "ended".
 */
export function useRunStream(
  runId: string | null,
  runEnded: boolean,
): { events: RunEvent[]; connection: ConnectionState } {
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const cursorRef = useRef(0);
  const endNowRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!runId) return;

    let es: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;
    let ended = false;

    const clearTimers = () => {
      if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
      if (retryTimer !== null) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
    };

    const finish = (state: ConnectionState) => {
      ended = true;
      if (es) {
        es.close();
        es = null;
      }
      clearTimers();
      if (!disposed) setConnection(state);
    };
    endNowRef.current = () => finish("ended");

    const append = (incoming: RunEvent[]) => {
      const cursor = cursorRef.current;
      const fresh = incoming.filter(
        (e) => e && typeof e.seq === "number" && e.seq > cursor,
      );
      if (fresh.length === 0) return;
      setEvents((prev) => {
        const seen = new Set(prev.map((e) => e.seq));
        const merged = prev.slice();
        for (const e of fresh) if (!seen.has(e.seq)) merged.push(e);
        merged.sort((a, b) => a.seq - b.seq);
        return merged;
      });
      cursorRef.current = Math.max(cursor, ...fresh.map((e) => e.seq));
      if (fresh.some((e) => e.type === "run.finish")) finish("ended");
    };

    const poll = async () => {
      try {
        const page = await api.getEvents(runId, cursorRef.current);
        if (disposed || ended) return;
        append(page.events ?? []);
        if (
          typeof page.next_cursor === "number" &&
          page.next_cursor > cursorRef.current
        ) {
          cursorRef.current = page.next_cursor;
        }
      } catch {
        /* unreachable — keep polling */
      }
    };

    const startPolling = () => {
      if (pollTimer !== null || ended || disposed) return;
      void poll();
      pollTimer = setInterval(() => void poll(), POLL_INTERVAL_MS);
    };

    const stopPolling = () => {
      if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const openStream = () => {
      if (ended || disposed) return;
      setConnection((c) => (c === "ended" ? c : "connecting"));
      const source = new EventSource(
        `${API_BASE}/api/runs/${encodeURIComponent(runId)}/stream?after=${cursorRef.current}`,
      );
      es = source;
      source.onopen = () => {
        if (disposed || ended) return;
        stopPolling();
        setConnection("live");
      };
      source.addEventListener("run_event", (ev: MessageEvent<string>) => {
        if (disposed || ended) return;
        try {
          append([JSON.parse(ev.data) as RunEvent]);
        } catch {
          /* malformed frame — skip */
        }
      });
      source.onerror = () => {
        if (disposed || ended) return;
        source.close();
        es = null;
        // Fall back to polling resync, retry SSE shortly after.
        setConnection("polling");
        startPolling();
        retryTimer = setTimeout(() => {
          stopPolling();
          openStream();
        }, SSE_RETRY_MS);
      };
    };

    setEvents([]);
    cursorRef.current = 0;
    openStream();

    return () => {
      disposed = true;
      ended = true;
      endNowRef.current = null;
      if (es) es.close();
      clearTimers();
    };
  }, [runId]);

  // Caller-observed end of run (manifest status != running).
  useEffect(() => {
    if (runEnded) endNowRef.current?.();
  }, [runEnded]);

  return { events, connection };
}
