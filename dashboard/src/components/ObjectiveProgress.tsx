"use client";

import { useState } from "react";
import {
  cx,
  IconCheck,
  IconChevron,
  Micro,
  Panel,
} from "./Bits";
import type { ObjectiveState } from "@/lib/types";

/**
 * Objective criteria checklist with done/total progress bar.
 * Criteria come from GET /api/runs/{id} → objective.criteria.
 */
export function ObjectiveProgress({
  objective,
}: {
  objective?: ObjectiveState | null;
}) {
  const [open, setOpen] = useState(true);

  const criteria = objective?.criteria ?? [];
  const total =
    typeof objective?.total === "number" && objective.total > 0
      ? objective.total
      : criteria.length;
  const done =
    typeof objective?.done === "number"
      ? objective.done
      : criteria.filter((c) => c.achieved).length;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  const achievedAll = objective?.achieved === true || (total > 0 && done >= total);

  return (
    <Panel>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-3 py-2.5 text-left focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70"
      >
        <Micro className="shrink-0">OBJECTIVE</Micro>
        <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-ink/85">
          {objective?.description || "awaiting objective data…"}
        </span>
        <span className="hidden h-1.5 w-28 shrink-0 overflow-hidden rounded-full bg-edge sm:block">
          <span
            className={cx(
              "block h-full rounded-full transition-all",
              achievedAll ? "bg-ok" : "bg-info",
            )}
            style={{ width: `${pct}%` }}
          />
        </span>
        <span
          className={cx(
            "shrink-0 font-mono text-[11px] tabular-nums",
            achievedAll ? "text-ok" : "text-muted",
          )}
        >
          {done}/{total}
        </span>
        <IconChevron
          className={cx(
            "h-3.5 w-3.5 shrink-0 text-muted transition-transform",
            !open && "rotate-180",
          )}
        />
      </button>

      {open && (
        <div className="scroll-slim max-h-56 overflow-y-auto border-t border-edge">
          {criteria.length === 0 ? (
            <p className="px-3 py-3 font-mono text-[11px] text-muted/70">
              No criteria reported yet.
            </p>
          ) : (
            <ul className="divide-y divide-edge/40">
              {criteria.map((c, i) => (
                <li
                  key={c.id || `crit-${i}`}
                  className="flex items-start gap-2.5 px-3 py-2"
                >
                  <span
                    className={cx(
                      "mt-[1px] flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
                      c.achieved
                        ? "border-ok/60 bg-ok/15 text-ok"
                        : "border-muted/40 text-transparent",
                    )}
                    aria-hidden
                  >
                    <IconCheck className="h-2.5 w-2.5" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p
                      className={cx(
                        "text-[12px] leading-snug",
                        c.achieved ? "text-ink" : "text-muted",
                      )}
                    >
                      {c.description || c.id}
                    </p>
                    {c.evidence && (
                      <p className="mt-0.5 line-clamp-2 font-mono text-[10px] leading-snug text-muted/60">
                        {c.evidence}
                      </p>
                    )}
                  </div>
                  <span
                    className={cx(
                      "shrink-0 font-mono text-[9px] tracking-[0.16em]",
                      c.achieved ? "text-ok" : "text-muted/50",
                    )}
                  >
                    {c.achieved ? "PASS" : "OPEN"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Panel>
  );
}
