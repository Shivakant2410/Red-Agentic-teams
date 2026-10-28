"use client";

import { useMemo, useState } from "react";
import {
  cx,
  ConfidenceChip,
  Micro,
  Panel,
  PanelHead,
  SeverityChip,
  severityTone,
  toneBorderL,
} from "./Bits";
import { fmtInt, truncate } from "@/lib/format";
import type { Finding } from "@/lib/types";

const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function severityRank(f: Finding): number {
  return SEV_RANK[(f.severity ?? "").toLowerCase()] ?? -1;
}

export function evidenceCount(f: Finding): number {
  if (Array.isArray(f.evidence)) return f.evidence.length;
  if (typeof f.evidence === "number") return f.evidence;
  if (f.proof) return 1;
  return 0;
}

/** Findings list with severity chips + expandable detail rows. */
export function FindingsTable({
  findings,
  className,
}: {
  findings: Finding[];
  className?: string;
}) {
  const [openKeys, setOpenKeys] = useState<Set<string>>(new Set());

  const sorted = useMemo(() => {
    return findings
      .map((f, i) => ({ f, i }))
      .sort((a, b) => severityRank(b.f) - severityRank(a.f) || a.i - b.i)
      .map(({ f }) => f);
  }, [findings]);

  const toggle = (key: string) =>
    setOpenKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const worst = sorted[0];

  return (
    <Panel className={className}>
      <PanelHead
        label="FINDINGS"
        right={
          <>
            {worst && (
              <SeverityChip severity={worst.severity} />
            )}
            <span className="font-mono text-[10px] tabular-nums text-muted">
              {fmtInt(sorted.length)}
            </span>
          </>
        }
      />
      {sorted.length === 0 ? (
        <p className="px-3 py-4 font-mono text-[11px] text-muted/70">
          No findings recorded yet.
        </p>
      ) : (
        <ul className="divide-y divide-edge/40">
          {sorted.map((f, i) => {
            const key = f.id || `finding-${i}-${f.title}`;
            const open = openKeys.has(key);
            const nEvidence = evidenceCount(f);
            return (
              <li key={key} className={cx("border-l-2", toneBorderL[severityTone(f.severity)])}>
                <button
                  type="button"
                  onClick={() => toggle(key)}
                  aria-expanded={open}
                  className="flex w-full items-center gap-2.5 px-3 py-2 text-left transition-colors hover:bg-panel2/50 focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70"
                >
                  <SeverityChip severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-[12.5px] text-ink/90">
                    {truncate(f.title, 110)}
                  </span>
                  <ConfidenceChip confidence={f.confidence} />
                  <span
                    className={cx(
                      "shrink-0 font-mono text-[10px] tabular-nums",
                      nEvidence > 0 ? "text-muted" : "text-muted/40",
                    )}
                    title="evidence items"
                  >
                    EV:{nEvidence}
                  </span>
                </button>
                {open && (
                  <div className="space-y-2 px-3 pb-3 pt-0.5 pl-[30px]">
                    {f.description && (
                      <p className="whitespace-pre-wrap break-words text-[12px] leading-relaxed text-ink/80">
                        {f.description}
                      </p>
                    )}
                    {f.proof && (
                      <div>
                        <Micro className="mb-1">PROOF</Micro>
                        <pre className="scroll-slim max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-edge bg-bg px-2 py-1.5 font-mono text-[10.5px] leading-relaxed text-ink/75">
                          {f.proof}
                        </pre>
                      </div>
                    )}
                    {Array.isArray(f.evidence) && f.evidence.length > 0 && (
                      <div>
                        <Micro className="mb-1">EVIDENCE</Micro>
                        <ul className="scroll-slim max-h-56 space-y-1 overflow-y-auto">
                          {f.evidence.map((e, j) => (
                            <li
                              key={j}
                              className="whitespace-pre-wrap break-words rounded border border-edge/70 bg-bg/60 px-2 py-1 font-mono text-[10.5px] leading-relaxed text-muted"
                            >
                              {typeof e === "string" ? e : JSON.stringify(e)}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {!f.description && !f.proof && !Array.isArray(f.evidence) && (
                      <p className="font-mono text-[10.5px] text-muted/60">
                        No detail available for this finding.
                      </p>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
