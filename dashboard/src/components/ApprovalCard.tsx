"use client";

import {
  btnAccent,
  btnOk,
  Chip,
  cx,
  IconCheck,
  IconX,
} from "./Bits";

export type ApprovalState = "pending" | "approved" | "denied";

/**
 * Inline approval decision card (rendered for approval.requested events).
 * Buttons POST /api/approvals/{id} {approve:bool} via the onDecision callback.
 */
export function ApprovalCard({
  id,
  action,
  details,
  state,
  busy,
  onDecision,
}: {
  id: string;
  action?: string;
  details?: string;
  state: ApprovalState;
  busy?: boolean;
  onDecision?: (id: string, approve: boolean) => void;
}) {
  const resolved = state !== "pending";
  return (
    <div
      className={cx(
        "rounded-md border bg-warn/5 px-2.5 py-2",
        resolved ? "border-edge" : "border-warn/40",
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[9.5px] tracking-[0.2em] text-warn">
          APPROVAL REQUESTED
        </span>
        <span className="font-mono text-[10px] text-muted/60">{id}</span>
        {resolved && (
          <Chip tone={state === "approved" ? "ok" : "accent"}>
            {state === "approved" ? "APPROVED" : "DENIED"}
          </Chip>
        )}
      </div>
      {action && (
        <div className="mt-1 break-words font-mono text-[11.5px] text-ink">
          {action}
        </div>
      )}
      {details && (
        <div className="mt-1 whitespace-pre-wrap break-words font-mono text-[10.5px] leading-relaxed text-muted">
          {details}
        </div>
      )}
      {!resolved && onDecision && (
        <div className="mt-2 flex gap-2">
          <button
            type="button"
            className={cx(btnOk, "px-2.5 py-1 text-[10px]")}
            disabled={busy}
            onClick={() => onDecision(id, true)}
          >
            <IconCheck className="h-3 w-3" />
            {busy ? "SENDING…" : "APPROVE"}
          </button>
          <button
            type="button"
            className={cx(btnAccent, "px-2.5 py-1 text-[10px]")}
            disabled={busy}
            onClick={() => onDecision(id, false)}
          >
            <IconX className="h-3 w-3" />
            DENY
          </button>
        </div>
      )}
    </div>
  );
}
