"use client";

import { cx, Dot, Panel, PanelHead } from "./Bits";
import { formatAge } from "@/lib/format";
import { useNow } from "@/lib/useNow";
import type { KillChainStage } from "@/lib/types";

/** Kill-chain stage tracker (achieved stages light up). */
export function KillChainList({
  stages,
  className,
}: {
  stages?: KillChainStage[];
  className?: string;
}) {
  const now = useNow(30_000);
  const list = stages ?? [];
  const achieved = list.filter((s) => s.achieved).length;

  return (
    <Panel className={className}>
      <PanelHead
        label="KILL CHAIN"
        right={
          <span className="font-mono text-[10px] tabular-nums text-muted">
            {achieved}/{list.length}
          </span>
        }
      />
      {list.length === 0 ? (
        <p className="px-3 py-4 font-mono text-[11px] text-muted/70">
          No kill-chain data yet.
        </p>
      ) : (
        <ol className="px-3 py-2">
          {list.map((s, i) => (
            <li key={s.stage || i} className="flex items-center gap-2.5 py-1.5">
              <Dot tone={s.achieved ? "ok" : "muted"} className={s.achieved ? undefined : "opacity-40"} />
              <span
                className={cx(
                  "font-mono text-[11px] uppercase tracking-[0.14em]",
                  s.achieved ? "text-ink" : "text-muted/70",
                )}
              >
                {s.stage}
              </span>
              {s.achieved && s.since && now != null && (
                <span className="ml-auto shrink-0 font-mono text-[9.5px] text-muted/50">
                  {formatAge(s.since, now)}
                </span>
              )}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}
