"use client";

import { useRouter } from "next/navigation";
import { cx, Panel, PanelHead } from "./Bits";
import { StatusBadge } from "./StatusBadge";
import { fmtInt, formatTokens, truncate } from "@/lib/format";
import { useNow } from "@/lib/useNow";
import { formatDuration, parseTs } from "@/lib/format";
import type { RunSummary } from "@/lib/types";

function StartedCell({ ts }: { ts?: string }) {
  const now = useNow(30_000);
  const t = parseTs(ts);
  if (t == null || now == null) return <span>—</span>;
  return <span title={new Date(t).toLocaleString()}>{formatDuration(Math.max(0, now - t))} ago</span>;
}

/** Runs overview table — click a row to open mission control for that run. */
export function RunsTable({ runs }: { runs: RunSummary[] }) {
  const router = useRouter();

  return (
    <Panel>
      <PanelHead
        label="RUNS"
        right={
          <span className="font-mono text-[10px] tabular-nums text-muted">
            {runs.length}
          </span>
        }
      />
      {runs.length === 0 ? (
        <p className="px-3 py-6 text-center font-mono text-[11px] text-muted/70">
          No runs yet — launch one from the panel.
          <span className="blink text-info">_</span>
        </p>
      ) : (
        <div className="scroll-slim overflow-x-auto">
          <table className="w-full min-w-[760px] border-collapse text-left">
            <thead>
              <tr className="border-b border-edge text-[9px] uppercase tracking-[0.18em] text-muted/70">
                <th className="px-3 py-2 font-medium">RUN ID</th>
                <th className="px-3 py-2 font-medium">ENGAGEMENT</th>
                <th className="px-3 py-2 font-medium">OBJECTIVE</th>
                <th className="px-3 py-2 font-medium">STATUS</th>
                <th className="px-3 py-2 text-right font-medium">STEPS</th>
                <th className="px-3 py-2 text-right font-medium">FINDINGS</th>
                <th className="px-3 py-2 text-right font-medium">TOKENS</th>
                <th className="px-3 py-2 text-right font-medium">STARTED</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr
                  key={r.run_id}
                  tabIndex={0}
                  role="link"
                  aria-label={`open run ${r.run_id}`}
                  onClick={() =>
                    router.push(`/runs?id=${encodeURIComponent(r.run_id)}`)
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      router.push(`/runs?id=${encodeURIComponent(r.run_id)}`);
                    }
                  }}
                  className={cx(
                    "cursor-pointer border-b border-edge/40 transition-colors last:border-0",
                    "hover:bg-panel2/60 focus-visible:bg-panel2/60 focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/60",
                  )}
                >
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-ink/90">
                    {r.run_id}
                  </td>
                  <td className="max-w-[180px] truncate px-3 py-2 text-[12px] text-ink/85" title={r.name}>
                    {r.name || "—"}
                  </td>
                  <td className="max-w-[280px] px-3 py-2 text-[12px] text-muted" title={r.objective}>
                    {truncate(r.objective, 90) || "—"}
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge status={r.status} />
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink/80">
                    {fmtInt(r.steps)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink/80">
                    {fmtInt(r.findings)}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-muted">
                    {formatTokens(r.tokens)}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right font-mono text-[10.5px] text-muted">
                    <StartedCell ts={r.started} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
