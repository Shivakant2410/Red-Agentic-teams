"use client";

import { cx, Dot, toneBgSoft, toneBorderSoft, toneFg } from "./Bits";

const STATUS_META: Record<
  string,
  { tone: "accent" | "ok" | "warn"; label: string; pulse?: boolean }
> = {
  running: { tone: "accent", label: "RUNNING", pulse: true },
  completed: { tone: "ok", label: "COMPLETED" },
  halted: { tone: "warn", label: "HALTED" },
  error: { tone: "accent", label: "ERROR" },
};

/**
 * Status badge per spec: running = pulsing red, completed = green,
 * halted = amber, error = red. Unknown statuses render muted.
 */
export function StatusBadge({
  status,
  className,
}: {
  status?: string | null;
  className?: string;
}) {
  const meta =
    (status ? STATUS_META[status.toLowerCase()] : undefined) || {
      tone: "muted" as const,
      label: (status || "UNKNOWN").toUpperCase(),
      pulse: false,
    };
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-2 py-0.5 font-mono text-[10px] tracking-[0.16em]",
        toneBorderSoft[meta.tone],
        toneBgSoft[meta.tone],
        toneFg[meta.tone],
        className,
      )}
    >
      <Dot tone={meta.tone} pulse={meta.pulse} />
      {meta.label}
    </span>
  );
}
