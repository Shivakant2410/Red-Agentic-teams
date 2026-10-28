"use client";

import { Fragment } from "react";
import { cx, Dot, Micro, Panel, toneFg, type Tone } from "./Bits";
import { Chip } from "./Bits";

const PHASES = ["recon", "exploit", "verify", "access", "logic"] as const;

const PHASE_TONE: Record<(typeof PHASES)[number], Tone> = {
  recon: "info",
  exploit: "accent",
  verify: "ok",
  access: "warn",
  logic: "purple",
};

/**
 * Horizontal mission phase stepper: RECON → EXPLOIT → VERIFY → ACCESS → LOGIC.
 * Derived from phase.change events (current phase highlighted, round shown).
 * Single-agent runs render a "SINGLE" marker instead.
 */
export function PhaseStepper({
  phase,
  round,
  multiAgent,
}: {
  phase?: string | null;
  round?: number | null;
  multiAgent: boolean;
}) {
  return (
    <Panel className="px-3 py-2.5">
      <div className="flex items-center justify-between gap-3">
        <Micro className="hidden shrink-0 sm:block">
          {multiAgent ? "PHASE" : "MODE"}
        </Micro>
        {multiAgent ? (
          <div className="scroll-slim flex min-w-0 flex-1 items-center overflow-x-auto">
            <StepperRow phase={phase} round={round} />
          </div>
        ) : (
          <div className="flex min-w-0 flex-1 items-center gap-2.5">
            <Chip tone="cyan">SINGLE</Chip>
            <span className="truncate font-mono text-[11px] text-muted">
              single-agent run · no swarm phases
            </span>
          </div>
        )}
      </div>
    </Panel>
  );
}

function StepperRow({
  phase,
  round,
}: {
  phase?: string | null;
  round?: number | null;
}) {
  const current = (phase ?? "").toLowerCase();
  const idx = PHASES.indexOf(current as (typeof PHASES)[number]);

  return (
    <div className="flex w-full items-center">
      {PHASES.map((p, i) => {
        const tone = PHASE_TONE[p];
        const isCurrent = i === idx;
        const isPast = idx >= 0 && i < idx;
        const isFuture = idx < 0 || i > idx;
        return (
          <Fragment key={p}>
            {i > 0 && (
              <div
                aria-hidden
                className={cx(
                  "h-px min-w-3 flex-1",
                  isFuture ? "bg-edge" : "bg-edge2",
                )}
              />
            )}
            <div className="flex shrink-0 items-center gap-1.5">
              <Dot
                tone={isFuture ? "muted" : tone}
                pulse={isCurrent}
                className={isFuture ? "opacity-40" : undefined}
              />
              <span
                className={cx(
                  "font-mono text-[10px] tracking-[0.18em]",
                  isCurrent
                    ? cx(toneFg[tone], "font-semibold")
                    : isPast
                      ? "text-ink/70"
                      : "text-muted/50",
                )}
              >
                {p.toUpperCase()}
              </span>
              {isCurrent && round != null && (
                <span className="rounded border border-edge2 bg-panel2 px-1 font-mono text-[9px] text-muted">
                  R{round}
                </span>
              )}
            </div>
          </Fragment>
        );
      })}
      {idx < 0 && (
        <span className="ml-3 shrink-0 font-mono text-[9.5px] tracking-[0.18em] text-muted/60">
          AWAITING PHASE
        </span>
      )}
    </div>
  );
}
