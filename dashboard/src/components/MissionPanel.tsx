"use client";

import { Chip, Micro, Panel } from "./Bits";
import { StatusBadge } from "./StatusBadge";
import { fmtInt } from "@/lib/format";
import type { Finding, MissionDetail } from "@/lib/types";

/**
 * Mission-specific visibility for adaptive runs (driver === "mission"), rendered
 * INSIDE the existing MissionControl — no second control plane.
 *
 * Honesty rules this panel follows:
 *  - a field the API does not expose renders as an explicit unavailable state,
 *    never a fabricated value (e.g. remaining budget);
 *  - task lifecycle status comes from the mission record (mission.json snapshot
 *    + journal tail via GET /api/missions/{id}) — a successful tool call is NOT
 *    task success;
 *  - confirmed findings are counted ONLY from FindingStore confidence
 *    ("confirmed" = the independent verifier reproduced it); everything else is
 *    "not yet confirmed".
 */
export function MissionPanel({
  mission,
  missionErr,
  findings,
}: {
  mission: MissionDetail | null;
  missionErr: string | null;
  findings: Finding[];
}) {
  const tasks = mission?.tasks ?? [];
  const byStatus = new Map<string, number>();
  for (const t of tasks) {
    const s = t.status ?? "unknown";
    byStatus.set(s, (byStatus.get(s) ?? 0) + 1);
  }
  const current = tasks.find(
    (t) => t.status === "running" || t.status === "claimed",
  );
  const confirmed = findings.filter((f) => f.confidence === "confirmed");
  const pendingVerification = findings.filter(
    (f) => f.confidence === "pending_verification",
  );
  const unconfirmedRest = findings.length
    - confirmed.length
    - pendingVerification.length
    - findings.filter((f) => f.confidence === "falsified").length
    - findings.filter((f) => f.confidence === "not_reproducible").length;

  const journalTail = (mission?.recent_events ?? []).slice(-3).reverse();

  return (
    <Panel data-testid="mission-panel">
      <div className="flex items-center gap-2 border-b border-edge px-3 py-2">
        <Micro>ADAPTIVE MISSION</Micro>
        <span className="ml-auto">
          <StatusBadge status={mission?.status} />
        </span>
      </div>

      <div className="space-y-2.5 px-3 py-2.5">
        {/* identity: mission and run are separate logical fields (same value today) */}
        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-3 gap-y-1 font-mono text-[10.5px]">
          <span className="text-muted/70">MISSION</span>
          <span className="min-w-0 truncate text-ink/90" title={mission?.mission_id}>
            {mission?.mission_id ?? "— unavailable (mission record not written yet)"}
          </span>
          <span className="text-muted/70">RUN</span>
          <span className="min-w-0 truncate text-ink/90" title={mission?.run_id}>
            {mission?.run_id ?? "—"}
          </span>
        </div>

        {/* current dispatch */}
        <div className="rounded-md border border-edge/60 bg-panel2/40 px-2.5 py-2">
          <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted/70">
            CURRENT TASK
          </div>
          {current ? (
            <div className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <Chip tone="info">{current.technique ?? "(no technique)"}</Chip>
              <span className="min-w-0 truncate text-ink/85" title={current.target}>
                {current.target ?? "(no target)"}
              </span>
              <span className="text-muted/70">
                {current.specialist ?? "specialist: —"}
                {typeof current.attempts === "number" ? ` · attempt ${current.attempts}` : ""}
              </span>
            </div>
          ) : (
            <div className="mt-1 font-mono text-[11px] text-muted/60">
              {mission ? "no task dispatching — scheduler between rounds" : "—"}
            </div>
          )}
        </div>

        {/* task lifecycle — execution states, not impact */}
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted/70">
            TASKS ({fmtInt(tasks.length)})
          </div>
          {tasks.length > 0 ? (
            <div className="mt-1 flex flex-wrap gap-1.5">
              {["succeeded", "failed", "running", "claimed", "pending",
                "blocked_duplicate", "expired", "cancelled"].map((s) =>
                byStatus.get(s) ? (
                  <Chip key={s} tone={s === "succeeded" ? "ok" : s === "failed" ? "accent" : "muted"}>
                    {s} {byStatus.get(s)}
                  </Chip>
                ) : null,
              )}
            </div>
          ) : (
            <div className="mt-1 font-mono text-[10.5px] text-muted/60">
              — no task snapshot available yet
            </div>
          )}
        </div>

        {/* verification authority: FindingStore + independent verifier ONLY */}
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted/70">
            VERIFICATION
          </div>
          <div className="mt-1 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
            <Chip tone="ok">confirmed {confirmed.length}</Chip>
            <Chip tone="warn">awaiting verifier {pendingVerification.length}</Chip>
            {unconfirmedRest > 0 && <Chip tone="muted">in pipeline {unconfirmedRest}</Chip>}
          </div>
          <p className="mt-1 text-[10px] leading-snug text-muted/60">
            &quot;confirmed&quot; = reproduced by the independent verification pipeline.
            Task success alone never confirms a finding.
          </p>
        </div>

        {/* stop reason + budget */}
        <div className="grid grid-cols-[auto_minmax(0,1fr)] items-baseline gap-x-3 gap-y-1 font-mono text-[10.5px]">
          <span className="text-muted/70">STOP REASON</span>
          <span className="min-w-0 break-words text-ink/85">
            {mission?.halt_reason ? mission.halt_reason : "— (none)"}
          </span>
          <span className="text-muted/70">BUDGET LEFT</span>
          <span className="text-muted/60" title="The mission API does not expose remaining budget yet">
            — not exposed by the API
          </span>
        </div>

        {/* journal tail: replanning / reflection visibility */}
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted/70">
            MISSION JOURNAL (TAIL)
          </div>
          {journalTail.length > 0 ? (
            <ul className="mt-1 space-y-0.5">
              {journalTail.map((ev, i) => (
                <li key={i} className="min-w-0 truncate font-mono text-[10.5px] text-muted/80">
                  {String(ev.type ?? "event")}
                  {ev.task_id ? ` · ${String(ev.task_id)}` : ""}
                  {ev.seq != null ? ` · #${String(ev.seq)}` : ""}
                </li>
              ))}
            </ul>
          ) : (
            <div className="mt-1 font-mono text-[10.5px] text-muted/60">— empty</div>
          )}
        </div>

        {missionErr && (
          <div className="font-mono text-[10px] leading-snug text-warn">
            mission record unavailable — {missionErr}
            {missionErr.includes("404") || missionErr.toLowerCase().includes("not found")
              ? " (mission.json is written by the driver once coordination starts)"
              : ""}
          </div>
        )}
      </div>
    </Panel>
  );
}
