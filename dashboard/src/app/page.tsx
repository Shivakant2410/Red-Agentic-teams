"use client";

import { useMemo } from "react";
import {
  Dot,
  LogoMark,
  Panel,
  cx,
} from "@/components/Bits";
import { LaunchRunPanel } from "@/components/LaunchRunPanel";
import { RunsTable } from "@/components/RunsTable";
import { StatCard } from "@/components/StatCard";
import { fmtInt } from "@/lib/format";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { Health } from "@/lib/types";

export default function RunsOverviewPage() {
  const health = usePoll(api.health, 10_000, "health");
  const { data: runsData, error: runsError } = usePoll(api.listRuns, null, "runs-init");
  const runs = useMemo(() => runsData?.runs ?? [], [runsData]);

  // Refresh every 5s while anything is active; back off when idle.
  const anyActive = runs.some((r) => (r.status ?? "").toLowerCase() === "running");
  usePoll(api.listRuns, anyActive ? 5_000 : 15_000, `runs-live-${anyActive}`);

  const stats = useMemo(() => {
    let active = 0;
    let findings = 0;
    for (const r of runs) {
      if ((r.status ?? "").toLowerCase() === "running") active += 1;
      findings += typeof r.findings === "number" ? r.findings : 0;
    }
    return { total: runs.length, active, findings };
  }, [runs]);

  const h: Health | null = health.data;
  const healthOk = h?.status === "ok";

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-edge bg-panel/80 backdrop-blur">
        <div className="mx-auto flex w-full max-w-[1440px] flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
          <LogoMark />
          <div className="leading-tight">
            <div className="flex items-baseline gap-2">
              <span className="text-[15px] font-semibold tracking-tight text-ink">
                RED TEAMS
              </span>
              <span className="font-mono text-[9.5px] uppercase tracking-[0.3em] text-muted">
                Mission Control
              </span>
            </div>
            <div className="font-mono text-[9px] tracking-[0.2em] text-muted/60">
              AUTONOMOUS RED-TEAM OPERATIONS
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <span
              className="flex items-center gap-2 rounded border border-edge bg-panel2/60 px-2.5 py-1"
              title={h ? `server ${h.status} · runs_root ${h.runs_root}` : undefined}
            >
              <Dot
                tone={healthOk ? "ok" : health.error ? "accent" : "muted"}
                pulse={healthOk}
              />
              <span className="font-mono text-[9.5px] tracking-[0.14em] text-muted">
                {healthOk
                  ? `API ONLINE · v${h?.version ?? "?"}`
                  : health.error
                    ? "API OFFLINE"
                    : "API …"}
              </span>
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-4">
        <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <StatCard label="TOTAL RUNS">{fmtInt(stats.total)}</StatCard>
          <StatCard label="ACTIVE RUNS">
            <span className={stats.active > 0 ? "text-accent" : "text-ink"}>
              {fmtInt(stats.active)}
            </span>
            {stats.active > 0 && (
              <span className="font-mono text-[9.5px] tracking-[0.16em] text-accent/80">
                <span className="blink">·</span> LIVE
              </span>
            )}
          </StatCard>
          <StatCard label="TOTAL FINDINGS">{fmtInt(stats.findings)}</StatCard>
        </section>

        <section className="mt-4 grid grid-cols-1 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_400px]">
          <div className="min-w-0 space-y-3">
            {runsError && (
              <div className="flex items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3 py-2">
                <Dot tone="accent" pulse />
                <span className="font-mono text-[11px] text-accent">
                  runs feed unavailable — {runsError}
                </span>
              </div>
            )}
            <RunsTable runs={runs} />
          </div>
          <LaunchRunPanel className="xl:sticky xl:top-4" />
        </section>
      </main>

      <footer className="mt-auto border-t border-edge pb-[env(safe-area-inset-bottom)]">
        <div className="mx-auto flex w-full max-w-[1440px] flex-wrap items-center justify-between gap-2 px-4 py-2.5 font-mono text-[9px] tracking-[0.2em] text-muted/50">
          <span>RED-AGENTIC-TEAMS · GEN-2 MISSION CONTROL</span>
          <span>AUTHORIZED ENGAGEMENTS ONLY</span>
        </div>
      </footer>
    </div>
  );
}
