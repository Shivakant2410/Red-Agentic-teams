"use client";

import { Chip, Panel, PanelHead } from "./Bits";
import { formatAge } from "@/lib/format";
import { useNow } from "@/lib/useNow";
import type { Reflection } from "@/lib/types";

/** LLM reflection loop feed: assessment + focus_next chips. */
export function ReflectionsFeed({
  reflections,
  className,
}: {
  reflections?: Reflection[];
  className?: string;
}) {
  const now = useNow(30_000);
  const list = reflections ?? [];

  return (
    <Panel className={className}>
      <PanelHead
        label="REFLECTIONS"
        right={
          <span className="font-mono text-[10px] tabular-nums text-muted">
            {list.length}
          </span>
        }
      />
      {list.length === 0 ? (
        <p className="px-3 py-4 font-mono text-[11px] text-muted/70">
          No reflections yet — the agent reflects periodically during long runs.
        </p>
      ) : (
        <ul className="scroll-slim max-h-80 divide-y divide-edge/40 overflow-y-auto">
          {list.map((r, i) => (
            <li key={r.ts || i} className="px-3 py-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[9.5px] tracking-[0.18em] text-warn">
                  CYCLE {list.length - i}
                </span>
                {now != null && (
                  <span className="ml-auto font-mono text-[9.5px] text-muted/50">
                    {formatAge(r.ts, now)}
                  </span>
                )}
              </div>
              <p className="mt-1 whitespace-pre-wrap break-words text-[12px] leading-relaxed text-ink/85">
                {r.assessment}
              </p>
              {r.adjustments && (
                <p className="mt-1 whitespace-pre-wrap break-words text-[11px] italic leading-relaxed text-muted">
                  {r.adjustments}
                </p>
              )}
              {r.focus_next && r.focus_next.length > 0 && (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {r.focus_next.map((f, j) => (
                    <Chip key={`${f}-${j}`} tone="warn">
                      {f}
                    </Chip>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
