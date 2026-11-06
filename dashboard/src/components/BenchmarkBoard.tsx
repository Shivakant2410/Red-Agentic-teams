"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { cx, Micro, Panel } from "@/components/Bits";
import { api } from "@/lib/api";
import { fmtInt } from "@/lib/format";
import { usePoll } from "@/lib/usePoll";
import type { BenchBoard as BenchBoardData, BenchCard } from "@/lib/types";

/**
 * Benchmark board — live scoreboard for the bench matrix (runs/bench-summary.json
 * served by GET /api/bench). Every element animates on mount and on data change:
 * cards rise in staggered, bars grow to width, numbers count up, achieved rows
 * pulse. Polls every 15s so a running harness fills the board live.
 */

function useCountUp(target: number, durationMs = 900): number {
  const [value, setValue] = useState(0);
  const fromRef = useRef(0);
  useEffect(() => {
    const from = fromRef.current;
    if (from === target) return;
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / durationMs);
      const eased = 1 - Math.pow(1 - p, 3); // easeOutCubic
      setValue(Math.round(from + (target - from) * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
      else fromRef.current = target;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);
  return value;
}

function Bar({ label, value, delayMs, tone }: {
  label: string; value: number; delayMs: number;
  tone: "ok" | "warn" | "muted";
}) {
  const [grown, setGrown] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setGrown(true), 60 + delayMs);
    return () => clearTimeout(t);
  }, [delayMs]);
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className="flex items-center gap-2">
      <span className="w-[64px] shrink-0 font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted">
        {label}
      </span>
      <div className="h-[5px] flex-1 overflow-hidden rounded-full bg-edge2/70">
        <div
          className={cx(
            "h-full rounded-full transition-[width] duration-[900ms] ease-out",
            tone === "ok" && "bg-emerald-400/80",
            tone === "warn" && "bg-amber-400/80",
            tone === "muted" && "bg-sky-400/60",
          )}
          style={{ width: grown ? `${pct}%` : "0%" }}
        />
      </div>
      <span className="w-[38px] shrink-0 text-right font-mono text-[10.5px] tabular-nums text-ink">
        {Math.round(pct)}%
      </span>
    </div>
  );
}

function VerdictChip({ achieved, confirmed }: { achieved: boolean; confirmed: number }) {
  if (achieved) {
    return (
      <span className="bench-pulse inline-flex items-center gap-1 rounded-full border border-emerald-400/40 bg-emerald-400/10 px-2 py-0.5 text-[9.5px] font-semibold uppercase tracking-[0.14em] text-emerald-300">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
        achieved
      </span>
    );
  }
  if (confirmed > 0) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 text-[9.5px] font-semibold uppercase tracking-[0.14em] text-amber-300">
        <span className="h-1.5 w-1.5 rounded-full bg-amber-300" />
        partial
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-edge2 bg-panel2/60 px-2 py-0.5 text-[9.5px] font-semibold uppercase tracking-[0.14em] text-muted">
      <span className="h-1.5 w-1.5 rounded-full bg-muted/60" />
      missed
    </span>
  );
}

function BenchCardView({ card, index }: { card: BenchCard; index: number }) {
  const completion = useCountUp(Math.round((card.completion ?? 0) * 100));
  const confirmed = useCountUp(card.confirmed ?? 0);
  const [open, setOpen] = useState(false);
  return (
    <Panel
      className={cx(
        "bench-rise cursor-pointer px-3 py-2.5 transition-colors hover:border-muted/40",
        card.objective_achieved && "border-emerald-400/25",
      )}
      style={{ animationDelay: `${index * 80}ms` }}
      onClick={() => setOpen((v) => !v)}
    >
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-[12.5px] font-semibold leading-tight text-ink">
            {card.target_key || card.target}
          </div>
          <div className="truncate font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted">
            {card.arm}
          </div>
        </div>
        <VerdictChip achieved={!!card.objective_achieved} confirmed={card.confirmed ?? 0} />
      </div>

      <div className="mb-2 flex items-end justify-between gap-2">
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-[26px] font-semibold leading-none tabular-nums text-ink">
            {completion}
          </span>
          <span className="font-mono text-[11px] text-muted">%</span>
          <span className="ml-1 text-[9.5px] uppercase tracking-[0.14em] text-muted">
            objective
          </span>
        </div>
        <div className="text-right">
          <span className="font-mono text-[15px] font-semibold leading-none tabular-nums text-ink">
            {confirmed}
          </span>
          <span className="ml-1 text-[9.5px] uppercase tracking-[0.14em] text-muted">
            confirmed
          </span>
        </div>
      </div>

      <div className="space-y-1.5">
        <Bar label="precision" value={card.precision ?? 0} delayMs={index * 80} tone="ok" />
        <Bar label="recall" value={card.recall ?? 0} delayMs={index * 80 + 120} tone="ok" />
      </div>

      <div
        className={cx(
          "overflow-hidden transition-[max-height,opacity] duration-300 ease-out",
          open ? "mt-2 max-h-24 opacity-100" : "max-h-0 opacity-0",
        )}
      >
        <div className="rounded-md border border-edge bg-bg px-2 py-1.5 font-mono text-[10px] leading-relaxed text-muted">
          <div>run {card.run_id}</div>
          <div>
            {fmtInt(card.steps ?? 0)} steps · {fmtInt(card.actions ?? 0)} actions ·{" "}
            {fmtInt(card.tokens ?? 0)} tokens · {fmtInt(card.elapsed_s ?? 0)}s
          </div>
          {card.halt_reason ? <div>halt: {card.halt_reason}</div> : null}
        </div>
      </div>
    </Panel>
  );
}

export function BenchmarkBoard() {
  const { data } = usePoll(api.bench, 15_000, "bench");
  const board: BenchBoardData | null = data;
  const [armFilter, setArmFilter] = useState<string | null>(null);
  const runs = useMemo(
    () => (board?.runs ?? []).filter((r) => !armFilter || r.arm === armFilter),
    [board, armFilter],
  );
  const confirmedTotal = useCountUp(board?.confirmed ?? 0);

  return (
    <section className="mt-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <Micro>BENCHMARK BOARD — objective completion · precision / recall · live</Micro>
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setArmFilter(null)}
            className={cx(
              "rounded-full border px-2 py-0.5 text-[9.5px] uppercase tracking-[0.14em] transition-colors",
              armFilter === null
                ? "border-muted/50 bg-panel2 text-ink"
                : "border-edge2 bg-panel2/60 text-muted hover:text-ink",
            )}
          >
            all arms
          </button>
          {(board?.arms ?? []).map((arm) => (
            <button
              key={arm}
              type="button"
              onClick={() => setArmFilter(armFilter === arm ? null : arm)}
              className={cx(
                "rounded-full border px-2 py-0.5 font-mono text-[9.5px] uppercase tracking-[0.14em] transition-colors",
                armFilter === arm
                  ? "border-muted/50 bg-panel2 text-ink"
                  : "border-edge2 bg-panel2/60 text-muted hover:text-ink",
              )}
            >
              {arm}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-2 grid grid-cols-3 gap-2">
        <Panel className="px-3 py-2">
          <Micro className="mb-1">runs</Micro>
          <div className="font-mono text-[17px] font-semibold leading-none tabular-nums text-ink">
            {board?.total ?? 0}
          </div>
        </Panel>
        <Panel className="px-3 py-2">
          <Micro className="mb-1">achieved</Micro>
          <div className="font-mono text-[17px] font-semibold leading-none tabular-nums text-emerald-300">
            {board?.achieved ?? 0}
          </div>
        </Panel>
        <Panel className="px-3 py-2">
          <Micro className="mb-1">confirmed findings</Micro>
          <div className="font-mono text-[17px] font-semibold leading-none tabular-nums text-ink">
            {confirmedTotal}
          </div>
        </Panel>
      </div>

      {runs.length === 0 ? (
        <Panel className="px-3 py-4 text-center font-mono text-[10.5px] text-muted">
          no bench cards yet — run scripts/e2e_bench_matrix.py (BENCH_LLM=zai|shim|openrouter)
        </Panel>
      ) : (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {runs.map((card, i) => (
            <BenchCardView key={card.run_id} card={card} index={i} />
          ))}
        </div>
      )}
    </section>
  );
}
