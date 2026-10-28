"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  Dot,
  LogoMark,
  Micro,
  Panel,
  Toast,
  btnAccent,
  btnGhost,
  cx,
  IconArrowUpRight,
  IconStop,
  type Tone,
} from "./Bits";
import { EventFeed } from "./EventFeed";
import { FindingsTable } from "./FindingsTable";
import { KillChainList } from "./KillChainList";
import { ObjectiveProgress } from "./ObjectiveProgress";
import { PhaseStepper } from "./PhaseStepper";
import { ReflectionsFeed } from "./ReflectionsFeed";
import { StatCard } from "./StatCard";
import { StatusBadge } from "./StatusBadge";
import type { ApprovalState } from "./ApprovalCard";
import { ApiError, api, errMessage, reportUrl } from "@/lib/api";
import { fmtInt, formatDuration, formatTokens, parseTs } from "@/lib/format";
import { useNow } from "@/lib/useNow";
import { usePoll } from "@/lib/usePoll";
import { useRunStream } from "@/lib/useRunStream";
import type { Finding, RunDetail } from "@/lib/types";

const REFRESH_MS = 5000;

/**
 * Mission control for a single run: /runs?id={run_id}.
 * Live event stream (SSE with polling fallback), stat row, phase stepper,
 * objective progress, findings / kill chain / reflections, approvals + stop.
 */
export default function MissionControl() {
  const params = useSearchParams();
  const runId = params.get("id");

  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [detailErr, setDetailErr] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [toast, setToast] = useState<{ id: number; message: string; tone: Tone } | null>(null);
  const [overrides, setOverrides] = useState<Record<string, ApprovalState>>({});
  const [busyApprovalId, setBusyApprovalId] = useState<string | null>(null);
  const [stopArmed, setStopArmed] = useState(false);
  const [stopping, setStopping] = useState(false);
  const armTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((message: string, tone: Tone) => {
    setToast({ id: Date.now(), message, tone });
  }, []);

  const ended = detail != null && (detail.status ?? "").toLowerCase() !== "running";
  const status = (detail?.status ?? "running").toLowerCase();

  /* ── run detail polling ─────────────────────────────────────────────────── */
  const refreshDetail = useCallback(async () => {
    if (!runId) return;
    try {
      const d = await api.getRun(runId);
      setDetail(d);
      setDetailErr(null);
      setNotFound(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setNotFound(true);
      } else {
        setDetailErr(errMessage(e));
      }
    }
  }, [runId]);

  useEffect(() => {
    if (!runId) return;
    setDetail(null);
    setDetailErr(null);
    setNotFound(false);
    setOverrides({});
    void refreshDetail();
    const iv = setInterval(() => void refreshDetail(), REFRESH_MS);
    return () => clearInterval(iv);
  }, [runId, refreshDetail]);

  /* ── live event stream ──────────────────────────────────────────────────── */
  const { events, connection } = useRunStream(runId, ended);

  /* ── pending approvals (safety net beside approval.* events) ────────────── */
  const approvals = usePoll(
    useCallback(
      () => (runId ? api.pendingApprovals(runId) : Promise.resolve({ pending: [] })),
      [runId],
    ),
    runId && !ended ? REFRESH_MS : null,
    `approvals-${runId}-${ended ? "ended" : "live"}`,
  );
  const pendingIds = useMemo(
    () => new Set((approvals.data?.pending ?? []).map((p) => p.id)),
    [approvals.data],
  );

  /* ── derived mission data ───────────────────────────────────────────────── */
  const lastPhaseEvent = useMemo(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === "phase.change") return events[i];
    }
    return null;
  }, [events]);

  const startEvent = useMemo(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === "run.start") return events[i];
    }
    return null;
  }, [events]);

  const multiAgent = !(
    typeof startEvent?.mode === "string" &&
    startEvent.mode.toLowerCase().includes("single")
  );

  const findings = useMemo<Finding[]>(() => {
    const base = detail?.findings ?? [];
    const merged = base.slice();
    const seen = new Set<string>();
    for (const f of base) seen.add(String(f.id ?? f.title ?? `base-${merged.length}`));
    for (const ev of events) {
      if (ev.type !== "finding.recorded" && ev.type !== "finding.confirmed") continue;
      const key = String(ev.id ?? ev.title ?? `ev-${ev.seq}`);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push({
        id: ev.id,
        title: ev.title ?? "(untitled finding)",
        severity: ev.severity ?? "info",
        confidence: ev.confidence,
      });
    }
    return merged;
  }, [detail, events]);

  const manifest = detail?.manifest;
  const name = manifest?.engagement || detail?.run_id || runId || "";
  const objectiveText = manifest?.objective || startEvent?.objective || "";

  const now = useNow(1000);
  const startedTs = parseTs(manifest?.started);
  const endTs = ended ? parseTs(manifest?.updated) ?? now : now;
  const elapsed =
    startedTs != null && endTs != null
      ? formatDuration(Math.max(0, endTs - startedTs))
      : "—";

  /* ── approvals state derivation + decisions ─────────────────────────────── */
  const resolvedFromEvents = useMemo(() => {
    const m = new Map<string, ApprovalState>();
    for (const ev of events) {
      if (ev.type === "approval.requested" && ev.id && !m.has(ev.id)) {
        m.set(ev.id, "pending");
      } else if (ev.type === "approval.resolved" && ev.id) {
        m.set(ev.id, ev.approved ? "approved" : "denied");
      }
    }
    return m;
  }, [events]);

  const approvalStateOf = useCallback(
    (id: string): ApprovalState => {
      if (overrides[id]) return overrides[id];
      if (pendingIds.has(id)) return "pending";
      return resolvedFromEvents.get(id) ?? "pending";
    },
    [overrides, pendingIds, resolvedFromEvents],
  );

  const onApproval = useCallback(
    async (id: string, approve: boolean) => {
      setBusyApprovalId(id);
      try {
        await api.resolveApproval(id, approve);
        setOverrides((o) => ({ ...o, [id]: approve ? "approved" : "denied" }));
        showToast(`approval ${id} ${approve ? "granted" : "denied"}`, approve ? "ok" : "warn");
        void approvals.refresh();
      } catch (e) {
        showToast(`approval ${id} failed — ${errMessage(e)} (expired?)`, "accent");
      } finally {
        setBusyApprovalId(null);
      }
    },
    [approvals, showToast],
  );

  /* ── stop (two-step confirm) ────────────────────────────────────────────── */
  const doStop = useCallback(async () => {
    if (!runId) return;
    setStopping(true);
    try {
      await api.stopRun(runId);
      showToast("STOP signal sent — waiting for the agent to halt", "warn");
      void refreshDetail();
    } catch (e) {
      showToast(`stop failed — ${errMessage(e)}`, "accent");
    } finally {
      setStopping(false);
      setStopArmed(false);
    }
  }, [runId, refreshDetail, showToast]);

  const onStopClick = () => {
    if (!detail || status !== "running" || stopping) return;
    if (!stopArmed) {
      setStopArmed(true);
      if (armTimer.current) clearTimeout(armTimer.current);
      armTimer.current = setTimeout(() => setStopArmed(false), 3500);
      return;
    }
    if (armTimer.current) clearTimeout(armTimer.current);
    void doStop();
  };

  useEffect(
    () => () => {
      if (armTimer.current) clearTimeout(armTimer.current);
    },
    [],
  );

  /* ── render ─────────────────────────────────────────────────────────────── */
  if (!runId) {
    return (
      <CenterNotice>
        <Panel className="px-6 py-5 text-center">
          <p className="font-mono text-[11px] tracking-[0.18em] text-muted">
            NO RUN SELECTED
          </p>
          <p className="mt-1 text-[12px] text-muted/70">
            Pick a run from the overview or launch a new one.
          </p>
          <Link href="/" className={cx(btnGhost, "mt-4")}>
            ← BACK TO RUNS
          </Link>
        </Panel>
      </CenterNotice>
    );
  }

  if (notFound) {
    return (
      <CenterNotice>
        <Panel className="px-6 py-5 text-center">
          <p className="font-mono text-[11px] tracking-[0.18em] text-accent">
            RUN NOT FOUND
          </p>
          <p className="mt-1 break-all font-mono text-[12px] text-muted">{runId}</p>
          <Link href="/" className={cx(btnGhost, "mt-4")}>
            ← BACK TO RUNS
          </Link>
        </Panel>
      </CenterNotice>
    );
  }

  return (
    <div className="flex min-h-screen flex-col lg:h-screen lg:overflow-hidden">
      {/* top bar */}
      <header className="sticky top-0 z-30 border-b border-edge bg-panel/95 backdrop-blur">
        <div className="mx-auto w-full max-w-[1600px] px-4 py-2.5">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <Link
              href="/"
              className="flex items-center gap-1.5 rounded border border-edge2 bg-panel2/60 px-2 py-1 font-mono text-[10px] tracking-[0.16em] text-muted transition-colors hover:border-muted/50 hover:text-ink focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70"
            >
              <span aria-hidden>←</span> RUNS
            </Link>
            <LogoMark className="hidden h-4 w-4 sm:block" />
            <span className="max-w-[240px] truncate font-mono text-[11px] text-ink/90" title={runId}>
              {runId}
            </span>
            <StatusBadge status={detail?.status} />
            <div className="ml-auto flex items-center gap-2">
              <a
                href={reportUrl(runId)}
                target="_blank"
                rel="noreferrer"
                className={cx(btnGhost, "px-2 py-1 text-[10px]")}
                title="Open the markdown report"
              >
                REPORT <IconArrowUpRight className="h-3 w-3" />
              </a>
              <button
                type="button"
                onClick={onStopClick}
                disabled={!detail || status !== "running" || stopping}
                className={cx(
                  btnAccent,
                  "px-2.5 py-1 text-[10px]",
                  stopArmed && "border-accent bg-accent/25 text-ink",
                )}
                title={
                  status !== "running"
                    ? "run is not active"
                    : stopArmed
                      ? "click again to confirm"
                      : "send STOP kill signal"
                }
              >
                <IconStop className="h-3 w-3" />
                {stopping
                  ? "STOPPING…"
                  : stopArmed
                    ? "CONFIRM STOP?"
                    : "STOP"}
              </button>
            </div>
          </div>
          <div className="mt-1.5 flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
            <span className="min-w-0 flex-1 truncate text-[12px] text-muted" title={objectiveText}>
              <span className="text-ink/85">{name}</span>
              {objectiveText ? ` — ${objectiveText}` : ""}
            </span>
            {ended && (
              <span className="font-mono text-[9.5px] tracking-[0.16em] text-muted/70">
                {status.toUpperCase()}
                {manifest?.halt_reason ? ` · HALT: ${manifest.halt_reason}` : ""}
              </span>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-[1600px] flex-1 flex-col gap-3 p-3 lg:min-h-0">
        {/* stat row */}
        <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatCard label="STATUS">
            <StatusBadge status={detail?.status} />
          </StatCard>
          <StatCard label="ELAPSED">
            <span className="text-[15px]">{elapsed}</span>
          </StatCard>
          <StatCard label="STEPS">{fmtInt(manifest?.steps ?? 0)}</StatCard>
          <StatCard label="FINDINGS">
            <span className={(manifest?.findings ?? 0) > 0 ? "text-warn" : undefined}>
              {fmtInt(manifest?.findings ?? findings.length)}
            </span>
          </StatCard>
          <StatCard label="TOKENS" className="col-span-2 sm:col-span-1">
            <span className="text-[15px]">{formatTokens(manifest?.tokens ?? 0)}</span>
          </StatCard>
        </section>

        {/* phase + objective */}
        <PhaseStepper
          phase={lastPhaseEvent?.phase}
          round={lastPhaseEvent?.round}
          multiAgent={multiAgent}
        />
        <ObjectiveProgress objective={detail?.objective} />

        {detailErr && (
          <div className="flex items-center gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-1.5">
            <Dot tone="warn" pulse />
            <span className="font-mono text-[10.5px] text-warn">
              detail poll failed — {detailErr} (showing last known state)
            </span>
          </div>
        )}

        {/* mission split */}
        <section className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_400px]">
          <div className="flex min-h-0 flex-col">
            <EventFeed
              className="h-[65vh] lg:h-auto lg:flex-1"
              events={events}
              connection={connection}
              approvalStateOf={approvalStateOf}
              approvalBusyId={busyApprovalId}
              onApproval={(id, approve) => void onApproval(id, approve)}
            />
          </div>
          <div className="scroll-slim flex min-h-0 flex-col gap-3 lg:overflow-y-auto lg:pr-1">
            <FindingsTable findings={findings} />
            <KillChainList stages={detail?.killchain} />
            <ReflectionsFeed reflections={detail?.reflections} />
          </div>
        </section>

        <p className="hidden text-center font-mono text-[9px] tracking-[0.2em] text-muted/40 lg:block">
          STREAM: SSE /API/RUNS/{runId}/STREAM · FALLBACK POLL 2S · DETAIL POLL 5S
        </p>
      </main>

      {detail == null && (
        <div className="pointer-events-none fixed inset-0 z-40 flex items-center justify-center bg-bg/70 backdrop-blur-sm">
          <div className="flex items-center gap-2.5 rounded-md border border-edge bg-panel px-4 py-2.5">
            <Dot tone="warn" pulse />
            <Micro>ESTABLISHING LINK · {runId}</Micro>
          </div>
        </div>
      )}

      {toast && (
        <Toast key={toast.id} message={toast.message} tone={toast.tone} onDone={() => setToast(null)} />
      )}
    </div>
  );
}

function CenterNotice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-bg p-6">
      {children}
    </div>
  );
}
