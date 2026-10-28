"use client";

import { memo, useState, type ReactNode } from "react";
import {
  Chip,
  cx,
  Dot,
  IconChevron,
  IconRefresh,
  IconZap,
  RoleChip,
  SeverityChip,
  severityTone,
  toneBorderL,
  ConfidenceChip,
} from "./Bits";
import { ApprovalCard, type ApprovalState } from "./ApprovalCard";
import { JsonView } from "./JsonView";
import { formatClock, oneLine, truncate } from "@/lib/format";
import type { RunEvent } from "@/lib/types";

export interface EventRowProps {
  event: RunEvent;
  approvalState?: ApprovalState;
  approvalBusy?: boolean;
  onApproval?: (id: string, approve: boolean) => void;
}

/** Common row shell: timestamp gutter + content. */
function Row({
  ts,
  children,
  className,
}: {
  ts: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cx(
        "flex items-start gap-2.5 px-3 py-1.5 transition-colors hover:bg-panel2/40",
        className,
      )}
    >
      <time className="w-[58px] shrink-0 select-none pt-[2px] text-right font-mono text-[9.5px] leading-4 text-muted/60 tabular-nums">
        {ts}
      </time>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

export const EventRow = memo(function EventRow({
  event: ev,
  approvalState = "pending",
  approvalBusy,
  onApproval,
}: EventRowProps) {
  const ts = formatClock(ev.ts);

  switch (ev.type) {
    case "agent.turn":
      return (
        <Row ts={ts}>
          <div className="rounded-md border border-edge bg-panel2/50">
            <div className="flex flex-wrap items-center gap-2 border-b border-edge/60 px-2.5 py-1.5">
              <RoleChip role={ev.role} />
              {typeof ev.step === "number" && (
                <span className="font-mono text-[9.5px] text-muted/70">
                  STEP {ev.step}
                </span>
              )}
              {ev.model && (
                <span className="truncate font-mono text-[9.5px] text-muted/60">
                  {ev.model}
                </span>
              )}
            </div>
            <div className="px-2.5 py-2">
              <ThoughtBody content={ev.content ?? ""} />
            </div>
          </div>
        </Row>
      );

    case "tool.call":
      return (
        <Row ts={ts}>
          <div className="rounded-md border border-edge/70 bg-bg/40 px-2.5 py-1.5">
            <div className="flex flex-wrap items-baseline gap-x-2 font-mono text-[11px]">
              <span className="text-muted/60">
                {ev.role ?? "agent"}
                {typeof ev.step === "number" ? `#${ev.step}` : ""}
              </span>
              <span className="font-medium text-ink">{ev.tool ?? "tool"}</span>
              {ev.args != null && (
                <span className="min-w-0 flex-1 truncate text-muted/50">
                  {oneLine(ev.args, 110)}
                </span>
              )}
            </div>
            {ev.args != null && (
              <JsonView value={ev.args} label="ARGS" className="mt-1 pl-1" />
            )}
          </div>
        </Row>
      );

    case "tool.result":
      return (
        <Row ts={ts}>
          <ToolResult
            tool={ev.tool}
            ok={ev.ok !== false}
            preview={ev.preview}
          />
        </Row>
      );

    case "finding.recorded":
    case "finding.confirmed":
      return (
        <Row ts={ts}>
          <FindingCard ev={ev} />
        </Row>
      );

    case "phase.change":
      return (
        <div className="flex items-center gap-3 px-3 py-2.5" role="separator">
          <div className="h-px flex-1 bg-edge" />
          <span className="shrink-0 font-mono text-[9.5px] tracking-[0.3em] text-info/90">
            PHASE · {(ev.phase ?? "?").toUpperCase()}
            {typeof ev.round === "number" ? ` · ROUND ${ev.round}` : ""}
          </span>
          <div className="h-px flex-1 bg-edge" />
        </div>
      );

    case "approval.requested":
      return (
        <Row ts={ts}>
          <ApprovalCard
            id={ev.id ?? "?"}
            action={ev.action}
            details={ev.details}
            state={approvalState}
            busy={approvalBusy}
            onDecision={onApproval}
          />
        </Row>
      );

    case "approval.resolved":
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span className="text-[9.5px] tracking-[0.2em] text-muted">
              APPROVAL
            </span>
            <span className="text-muted/70">{ev.id}</span>
            <span className="text-muted/50">→</span>
            <Chip tone={ev.approved ? "ok" : "accent"}>
              {ev.approved ? "APPROVED" : "DENIED"}
            </Chip>
          </div>
        </Row>
      );

    case "swarm.claim":
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span className="flex items-center gap-1 font-semibold text-purple">
              <IconZap className="h-3 w-3" />
              SWARM
            </span>
            <span className="text-ink/90">{ev.worker ?? "worker"}</span>
            <span className="text-muted/50">claimed</span>
            <span className="text-cyan">{ev.technique ?? "technique"}</span>
            {ev.target && (
              <>
                <span className="text-muted/50">→</span>
                <span className="truncate text-ink/75">{ev.target}</span>
              </>
            )}
          </div>
        </Row>
      );

    case "reflection":
      return (
        <Row ts={ts}>
          <div className="rounded-md border border-warn/25 bg-warn/5 px-2.5 py-2">
            <div className="font-mono text-[9.5px] tracking-[0.2em] text-warn">
              REFLECTION
            </div>
            <p className="mt-1 whitespace-pre-wrap break-words text-[12px] leading-relaxed text-ink/90">
              {ev.assessment ?? ""}
            </p>
            {ev.adjustments && (
              <p className="mt-1 whitespace-pre-wrap break-words text-[11px] italic leading-relaxed text-muted">
                {ev.adjustments}
              </p>
            )}
            {ev.focus_next && ev.focus_next.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {ev.focus_next.map((f, i) => (
                  <Chip key={`${f}-${i}`} tone="warn">
                    {f}
                  </Chip>
                ))}
              </div>
            )}
          </div>
        </Row>
      );

    case "llm.rotate":
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-muted">
            <span className="flex items-center gap-1 text-info/90">
              <IconRefresh className="h-3 w-3" />
              LLM ROTATE
            </span>
            <span className="text-ink/85">{ev.model ?? "?"}</span>
            {ev.reason && (
              <span className="text-muted/70">({ev.reason})</span>
            )}
          </div>
        </Row>
      );

    case "run.start":
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span className="flex items-center gap-1.5 font-semibold tracking-[0.16em] text-ok">
              <Dot tone="ok" pulse />
              RUN START
            </span>
            {ev.mode && <Chip tone="cyan">{ev.mode}</Chip>}
            {ev.engagement && (
              <span className="min-w-0 truncate text-muted">
                {truncate(ev.engagement, 64)}
              </span>
            )}
            {ev.objective && (
              <span className="min-w-0 flex-1 truncate text-muted/60">
                {truncate(ev.objective, 120)}
              </span>
            )}
          </div>
        </Row>
      );

    case "run.finish":
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-md border border-edge bg-panel2/60 px-2.5 py-2 font-mono text-[11px]">
            <span className="flex items-center gap-1.5 font-semibold tracking-[0.16em]">
              <Dot
                tone={
                  (ev.status ?? "").toLowerCase() === "completed"
                    ? "ok"
                    : (ev.status ?? "").toLowerCase() === "halted"
                      ? "warn"
                      : "accent"
                }
              />
              RUN FINISH
            </span>
            <Chip
              tone={
                (ev.status ?? "").toLowerCase() === "completed"
                  ? "ok"
                  : (ev.status ?? "").toLowerCase() === "halted"
                    ? "warn"
                    : "accent"
              }
            >
              {(ev.status ?? "ended").toUpperCase()}
            </Chip>
            <span className="text-muted">
              {ev.findings ?? 0} findings · {ev.tokens ?? 0} tokens
            </span>
            {ev.halt_reason && (
              <span className="min-w-0 flex-1 truncate text-muted/70">
                halt: {ev.halt_reason}
              </span>
            )}
          </div>
        </Row>
      );

    case "objective.progress":
      return (
        <Row ts={ts}>
          <ObjectiveProgressInline done={ev.done} total={ev.total} />
        </Row>
      );

    default:
      // Unknown event type — render defensively so novel server events surface.
      return (
        <Row ts={ts}>
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-muted/80">
            <Chip tone="muted">{ev.type}</Chip>
            <span className="min-w-0 flex-1 truncate">
              {oneLine(omitMeta(ev), 140)}
            </span>
          </div>
        </Row>
      );
  }
});

/* ── pieces ──────────────────────────────────────────────────────────────── */

function ThoughtBody({ content }: { content: string }) {
  const [open, setOpen] = useState(false);
  const long = content.length > 900 || content.split("\n").length > 14;
  return (
    <div>
      <div
        className={cx(
          "whitespace-pre-wrap break-words text-[12.5px] leading-relaxed text-ink/90",
          long && !open && "max-h-44 overflow-hidden [mask-image:linear-gradient(to_bottom,black_78%,transparent)]",
        )}
      >
        {content}
      </div>
      {long && (
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="mt-1 inline-flex items-center gap-1 font-mono text-[9.5px] tracking-[0.16em] text-info/90 transition-colors hover:text-info"
        >
          <IconChevron
            className={cx("h-3 w-3 transition-transform", open && "rotate-180")}
          />
          {open ? "COLLAPSE" : "EXPAND"}
        </button>
      )}
    </div>
  );
}

function ToolResult({
  tool,
  ok,
  preview,
}: {
  tool?: string;
  ok: boolean;
  preview?: string;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div
      className={cx(
        "ml-2 rounded border-l-2 bg-panel2/30 py-1 pl-2.5 pr-2",
        ok ? "border-l-ok/70" : "border-l-accent/80",
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-baseline gap-2 text-left font-mono text-[10.5px]"
      >
        <span className={ok ? "text-ok" : "text-accent"}>
          {ok ? "OK" : "FAILED"}
        </span>
        <span className="shrink-0 text-muted/80">{tool ?? "tool"}</span>
        <span className="min-w-0 flex-1 truncate text-ink/50">
          {oneLine(preview ?? "", 160)}
        </span>
        <IconChevron
          className={cx(
            "h-3 w-3 shrink-0 self-center text-muted/70 transition-transform",
            open && "rotate-180",
          )}
        />
      </button>
      {open && preview && (
        <pre className="scroll-slim mt-1.5 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded border border-edge bg-bg px-2 py-1.5 font-mono text-[10.5px] leading-relaxed text-ink/75">
          {preview}
        </pre>
      )}
    </div>
  );
}

function FindingCard({ ev }: { ev: RunEvent }) {
  const confirmed = ev.type === "finding.confirmed";
  const tone = severityTone(ev.severity);
  return (
    <div
      className={cx(
        "rounded-md border border-l-2 bg-panel2/60 px-2.5 py-2",
        confirmed ? "border-l-ok" : toneBorderL[tone],
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <span
          className={cx(
            "font-mono text-[9.5px] tracking-[0.2em]",
            confirmed ? "text-ok" : "text-muted",
          )}
        >
          {confirmed ? "FINDING CONFIRMED" : "FINDING RECORDED"}
        </span>
        <SeverityChip severity={ev.severity} />
        <ConfidenceChip confidence={ev.confidence} />
      </div>
      <div className="mt-1 break-words text-[12.5px] font-medium text-ink">
        {ev.title ?? "(untitled finding)"}
      </div>
      {ev.id && (
        <div className="mt-0.5 font-mono text-[9.5px] text-muted/50">{ev.id}</div>
      )}
    </div>
  );
}

function ObjectiveProgressInline({
  done,
  total,
}: {
  done?: number;
  total?: number;
}) {
  const d = typeof done === "number" ? done : 0;
  const t = typeof total === "number" ? total : 0;
  const pct = t > 0 ? Math.min(100, Math.round((d / t) * 100)) : 0;
  return (
    <div className="flex items-center gap-2.5 font-mono text-[10.5px]">
      <span className="tracking-[0.2em] text-ok/90">OBJECTIVE</span>
      <span className="h-1 w-28 overflow-hidden rounded-full bg-edge">
        <span
          className="block h-full rounded-full bg-ok transition-all"
          style={{ width: `${pct}%` }}
        />
      </span>
      <span className="tabular-nums text-muted">
        {d}/{t}
      </span>
    </div>
  );
}

function omitMeta(ev: RunEvent): Record<string, unknown> {
  const { seq: _seq, ts: _ts, run_id: _run_id, type: _type, ...rest } = ev;
  return rest;
}
