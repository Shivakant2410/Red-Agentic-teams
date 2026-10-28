"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  cx,
  Dot,
  Panel,
  PanelHead,
  type Tone,
} from "./Bits";
import { EventRow } from "./EventRow";
import type { ApprovalState } from "./ApprovalCard";
import type { RunEvent } from "@/lib/types";
import type { ConnectionState } from "@/lib/useRunStream";

export type EventFilter =
  | "all"
  | "thoughts"
  | "tools"
  | "findings"
  | "approvals"
  | "system";

const FILTERS: { id: EventFilter; label: string; types: string[] }[] = [
  { id: "all", label: "ALL", types: [] },
  { id: "thoughts", label: "THOUGHTS", types: ["agent.turn"] },
  { id: "tools", label: "TOOLS", types: ["tool.call", "tool.result"] },
  {
    id: "findings",
    label: "FINDINGS",
    types: ["finding.recorded", "finding.confirmed"],
  },
  {
    id: "approvals",
    label: "APPROVALS",
    types: ["approval.requested", "approval.resolved"],
  },
  {
    id: "system",
    label: "SYSTEM",
    types: [
      "run.start",
      "run.finish",
      "phase.change",
      "objective.progress",
      "swarm.claim",
      "reflection",
      "llm.rotate",
    ],
  },
];

function matchesFilter(ev: RunEvent, filter: EventFilter): boolean {
  if (filter === "all") return true;
  const def = FILTERS.find((f) => f.id === filter);
  return def ? def.types.includes(ev.type) : true;
}

const CONN_META: Record<
  ConnectionState,
  { tone: Tone; label: string; pulse: boolean }
> = {
  live: { tone: "ok", label: "LIVE", pulse: true },
  connecting: { tone: "warn", label: "CONNECTING", pulse: true },
  polling: { tone: "warn", label: "RECONNECTING", pulse: true },
  ended: { tone: "muted", label: "ENDED", pulse: false },
};

export interface EventFeedProps {
  events: RunEvent[];
  connection: ConnectionState;
  approvalStateOf: (id: string) => ApprovalState;
  approvalBusyId?: string | null;
  onApproval?: (id: string, approve: boolean) => void;
  className?: string;
}

/**
 * The centerpiece: live, filterable, auto-scrolling event feed.
 * Follows the stream via SSE (handled upstream); pauses auto-scroll when the
 * operator scrolls up and offers a resume button with a missed-events count.
 */
export function EventFeed({
  events,
  connection,
  approvalStateOf,
  approvalBusyId,
  onApproval,
  className,
}: EventFeedProps) {
  const [filter, setFilter] = useState<EventFilter>("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const [missed, setMissed] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  autoScrollRef.current = autoScroll;

  const filtered = useMemo(
    () => events.filter((ev) => matchesFilter(ev, filter)),
    [events, filter],
  );

  const counts = useMemo(() => {
    const map = new Map<EventFilter, number>();
    for (const f of FILTERS) map.set(f.id, 0);
    for (const ev of events) {
      for (const f of FILTERS) {
        if (f.id !== "all" && f.types.includes(ev.type)) {
          map.set(f.id, (map.get(f.id) ?? 0) + 1);
        }
      }
    }
    return map;
  }, [events]);

  // Follow the tail while auto-scroll is engaged.
  useEffect(() => {
    if (!autoScroll) return;
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [filtered.length, autoScroll]);

  // Count events arriving while the operator has scrolled away.
  useEffect(() => {
    if (!autoScroll) setMissed((m) => m + 1);
  }, [events.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const onScroll = useCallback(() => {
    const el = listRef.current;
    if (!el) return;
    const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (autoScrollRef.current && distance > 80) setAutoScroll(false);
  }, []);

  const resume = () => {
    setMissed(0);
    setAutoScroll(true);
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  };

  const conn = CONN_META[connection];

  return (
    <Panel className={cx("flex min-h-0 flex-col overflow-hidden", className)}>
      <PanelHead
        label="EVENT FEED"
        right={
          <>
            <span className="hidden font-mono text-[9.5px] text-muted/50 tabular-nums md:inline">
              {filtered.length}/{events.length}
            </span>
            <span
              className={cx(
                "flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-[9px] tracking-[0.16em]",
                conn.tone === "ok"
                  ? "border-ok/30 bg-ok/10 text-ok"
                  : conn.tone === "warn"
                    ? "border-warn/30 bg-warn/10 text-warn"
                    : "border-edge2 bg-panel2 text-muted",
              )}
              title={`stream state: ${connection}`}
            >
              <Dot tone={conn.tone} pulse={conn.pulse} />
              {conn.label}
            </span>
          </>
        }
      />

      {/* filter chips */}
      <div className="flex flex-wrap items-center gap-1 border-b border-edge/60 px-2.5 py-1.5">
        {FILTERS.map((f) => {
          const active = filter === f.id;
          const n = f.id === "all" ? events.length : (counts.get(f.id) ?? 0);
          return (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              aria-pressed={active}
              className={cx(
                "rounded border px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.14em] transition-colors",
                active
                  ? "border-info/50 bg-info/10 text-info"
                  : "border-edge bg-transparent text-muted/80 hover:border-edge2 hover:text-ink",
              )}
            >
              {f.label}
              <span className={cx("ml-1 tabular-nums", active ? "text-info/70" : "text-muted/40")}>
                {n}
              </span>
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => (autoScroll ? setAutoScroll(false) : resume())}
          aria-pressed={autoScroll}
          className={cx(
            "ml-auto rounded border px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.14em] transition-colors",
            autoScroll
              ? "border-ok/40 bg-ok/10 text-ok"
              : "border-edge text-muted hover:border-edge2 hover:text-ink",
          )}
          title="Follow the tail of the stream"
        >
          {autoScroll ? "AUTO-SCROLL ON" : "AUTO-SCROLL OFF"}
        </button>
      </div>

      {/* event list */}
      <div
        ref={listRef}
        onScroll={onScroll}
        className="scroll-slim relative min-h-0 flex-1 overflow-y-auto"
      >
        {filtered.length === 0 ? (
          <EmptyFeed connection={connection} hasEvents={events.length > 0} />
        ) : (
          <div className="divide-y divide-edge/35">
            {filtered.map((ev) => (
              <EventRow
                key={ev.seq}
                event={ev}
                approvalState={
                  ev.type === "approval.requested" && ev.id
                    ? approvalStateOf(ev.id)
                    : undefined
                }
                approvalBusy={ev.id ? approvalBusyId === ev.id : undefined}
                onApproval={onApproval}
              />
            ))}
          </div>
        )}

        {/* resume-follow pill */}
        {!autoScroll && (
          <button
            type="button"
            onClick={resume}
            className="sticky bottom-3 left-1/2 z-10 flex -translate-x-1/2 items-center gap-1.5 rounded-full border border-info/50 bg-panel px-3 py-1 font-mono text-[10px] tracking-[0.14em] text-info shadow-lg shadow-black/40 transition-colors hover:bg-info/10"
          >
            <Dot tone="info" pulse />
            RESUME FOLLOW
            {missed > 0 && (
              <span className="text-info/70">(+{missed})</span>
            )}
          </button>
        )}
      </div>
    </Panel>
  );
}

function EmptyFeed({
  connection,
  hasEvents,
}: {
  connection: ConnectionState;
  hasEvents: boolean;
}) {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      <Dot tone={connection === "live" ? "ok" : "muted"} pulse={connection === "live"} />
      <p className="font-mono text-[11px] tracking-[0.18em] text-muted">
        {hasEvents ? "NO EVENTS MATCH THIS FILTER" : "WAITING FOR AGENT ACTIVITY"}
        <span className="blink text-info">_</span>
      </p>
      <p className="max-w-xs text-[11px] leading-relaxed text-muted/60">
        {connection === "ended"
          ? "This run has ended and its event log is closed."
          : "Agent thoughts, tool calls, findings and approvals will appear here in real time."}
      </p>
    </div>
  );
}
