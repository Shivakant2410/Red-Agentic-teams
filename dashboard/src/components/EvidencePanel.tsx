"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, errMessage } from "@/lib/api";
import type { Finding } from "@/lib/types";

type EvidenceTab = "graph" | "traffic" | "proxy" | "coverage" | "inventory" | "recon" | "poe" | "retest";
const TABS: { id: EvidenceTab; label: string }[] = [
  { id: "graph", label: "GRAPH" },
  { id: "traffic", label: "TRAFFIC" },
  { id: "proxy", label: "PROXY" },
  { id: "coverage", label: "COVERAGE" },
  { id: "inventory", label: "INVENTORY" },
  { id: "recon", label: "RECON LIVE" },
  { id: "poe", label: "POE" },
  { id: "retest", label: "RETEST" },
];

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function safeView(tab: EvidenceTab, value: unknown): unknown {
  const root = record(value);
  if (tab === "traffic") {
    const rows = Array.isArray(root.traffic) ? root.traffic : [];
    return {
      next_cursor: root.next_cursor,
      traffic: rows.map((item) => {
        const row = record(item);
        return {
          seq: row.seq, ts: row.ts, method: row.method, url: row.url,
          status: row.status, elapsed_ms: row.elapsed_ms,
          source: row.source, tool: row.tool,
        };
      }),
      note: "Request/response headers and bodies are intentionally omitted from this view.",
    };
  }
  if (tab === "poe") {
    const rows = Array.isArray(root.findings) ? root.findings : [];
    return {
      summary: root.summary,
      findings: rows.map((item) => {
        const row = record(item);
        return {
          id: row.id, title: row.title, confidence: row.confidence,
          evidence_ref: row.evidence_ref, exchange_seq: row.exchange_seq,
          level: row.level, verified: row.verified, note: row.note,
        };
      }),
    };
  }
  if (tab === "inventory") {
    const hosts = record(root.hosts);
    return { summary: root.summary, hosts: Object.keys(hosts).slice(0, 100) };
  }
  if (tab === "retest") {
    const rows = Array.isArray(root.retests) ? root.retests : [];
    return {
      run_id: root.run_id,
      summary: root.summary,
      retests: rows.map((item) => {
        const row = record(item);
        return { finding_id: row.finding_id, verdict: row.verdict,
          status: row.status, trials: row.trials, passed: row.passed,
          reason: row.reason };
      }),
    };
  }
  return value;
}

export function EvidencePanel({ runId, findings }: { runId: string; findings: Finding[] }) {
  const [tab, setTab] = useState<EvidenceTab>("graph");
  const [payload, setPayload] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [findingId, setFindingId] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      let result: Record<string, unknown>;
      switch (tab) {
        case "graph": result = await api.getGraph(runId); break;
        case "traffic": result = await api.getTraffic(runId); break;
        case "proxy": result = await api.getProxy(runId); break;
        case "coverage": result = await api.getCoverage(runId); break;
        case "inventory": result = await api.getInventory(runId); break;
        case "recon": result = await api.getReconLive(runId); break;
        case "poe": result = await api.getPoe(runId); break;
        case "retest": return;
      }
      setPayload(result);
    } catch (e) {
      setPayload(null);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [runId, tab]);

  useEffect(() => {
    if (tab !== "retest") void load();
    else { setPayload(null); setError(null); }
  }, [tab, load]);

  const view = useMemo(() => safeView(tab, payload), [tab, payload]);
  const replayable = findings.filter((finding) => typeof finding.id === "string" && finding.id.length > 0);

  const runRetest = useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await api.retestRun(runId, { finding_id: findingId });
      setPayload(result);
    } catch (e) {
      setPayload(null);
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [findingId, runId]);

  return (
    <section className="rounded-lg border border-edge bg-panel p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-mono text-[10px] tracking-[0.16em] text-muted">RUN EVIDENCE</p>
          <p className="mt-0.5 text-[11px] text-muted/70">Read-only artifact views · retest requires an explicit operator action</p>
        </div>
        {tab !== "retest" && (
          <button type="button" onClick={() => void load()} disabled={loading}
            className="rounded border border-edge2 px-2 py-1 font-mono text-[9px] text-muted hover:text-ink disabled:opacity-40">
            {loading ? "LOADING…" : "REFRESH"}
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Run evidence views">
        {TABS.map((item) => (
          <button key={item.id} type="button" role="tab" aria-selected={tab === item.id}
            onClick={() => setTab(item.id)}
            className={tab === item.id
              ? "rounded border border-info/60 bg-info/10 px-2 py-1 font-mono text-[9px] tracking-[0.08em] text-ink"
              : "rounded border border-edge2 px-2 py-1 font-mono text-[9px] tracking-[0.08em] text-muted hover:text-ink"}>
            {item.label}
          </button>
        ))}
      </div>
      {tab === "retest" && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <select aria-label="Finding to retest" value={findingId} onChange={(event) => setFindingId(event.target.value)}
            className="min-w-0 flex-1 rounded border border-edge2 bg-panel2 px-2 py-1.5 text-[11px] text-ink">
            <option value="">Select a finding with a stored replay recipe</option>
            {replayable.map((finding) => <option key={finding.id} value={finding.id}>{finding.title}</option>)}
          </select>
          <button type="button" onClick={() => void runRetest()} disabled={!findingId || loading}
            className="rounded border border-warn/50 bg-warn/10 px-2.5 py-1.5 font-mono text-[9px] text-ink disabled:opacity-40">
            {loading ? "REPLAYING…" : "REPLAY PROOF"}
          </button>
          <p className="w-full text-[10px] text-muted/70">Replays the selected proof against the target under this run's frozen scope.</p>
        </div>
      )}
      {error && <p role="alert" className="mt-2 text-[10px] text-warn">{error}</p>}
      {payload != null && (
        <pre className="mt-3 max-h-72 overflow-auto rounded bg-bg/70 p-2 text-[9px] leading-relaxed text-muted">
          {JSON.stringify(view, null, 2).slice(0, 12000)}
        </pre>
      )}
      {payload == null && !error && tab !== "retest" && loading && (
        <p className="mt-3 font-mono text-[10px] text-muted">Loading {tab}…</p>
      )}
      {tab === "retest" && payload == null && !error && !loading && (
        <p className="mt-3 text-[10px] text-muted">Choose a finding and explicitly replay its proof. No target traffic is sent until you press the button.</p>
      )}
    </section>
  );
}
