"use client";

import { Panel, Micro } from "./Bits";
import type { RunDetail } from "@/lib/types";

/**
 * Discovered assets / attack-surface panel (Builder 04): renders the run's
 * knowledge-graph layers (hosts, endpoints, parameters) straight from run
 * detail — the same canonical KG the agents write. Missing layers render as
 * honest empty states (a round-one run is partial, never fabricated).
 */
export function AssetsPanel({ detail }: { detail: RunDetail | null }) {
  const graph = detail?.graph ?? {};
  const hosts = Array.isArray(graph.hosts) ? graph.hosts : [];
  const endpoints = Array.isArray(graph.endpoints) ? graph.endpoints : [];
  const params = Array.isArray(graph.params) ? graph.params : [];

  const shown = endpoints.slice(0, 12) as Record<string, unknown>[];
  const nodeLabel = (n: Record<string, unknown>): string =>
    String(n.key ?? n.url ?? n.value ?? n.name ?? "?");
  const nodeDoc = (n: Record<string, unknown>): string => {
    const attrs = (n.attrs ?? {}) as Record<string, unknown>;
    return String(attrs.doc ?? attrs.title ?? "");
  };

  return (
    <Panel>
      <div className="flex items-center justify-between border-b border-edge px-3 py-2">
        <Micro>DISCOVERED ASSETS</Micro>
        <span className="font-mono text-[9px] tracking-[0.14em] text-muted/60">
          {hosts.length} HOSTS · {endpoints.length} ENDPOINTS · {params.length} PARAMS
        </span>
      </div>
      {hosts.length === 0 && endpoints.length === 0 ? (
        <p className="px-3 py-2 text-[10.5px] leading-snug text-muted/60">
          No assets discovered yet — the map fills as recon progresses.
        </p>
      ) : (
        <div className="space-y-2 px-3 py-2">
          {hosts.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {(hosts.slice(0, 6) as Record<string, unknown>[]).map((h, i) => (
                <span
                  key={`h-${i}`}
                  className="rounded border border-edge bg-panel2/40 px-1.5 py-0.5 font-mono text-[10px] text-ink/90"
                >
                  {nodeLabel(h)}
                </span>
              ))}
            </div>
          )}
          <ul className="space-y-1">
            {shown.map((e, i) => (
              <li key={`e-${i}`} className="flex items-baseline gap-2 font-mono text-[10.5px] leading-snug">
                <span className="min-w-0 truncate text-ink/90" title={nodeDoc(e) || nodeLabel(e)}>
                  {nodeLabel(e)}
                </span>
                {nodeDoc(e) && (
                  <span className="min-w-0 truncate text-muted/60">{nodeDoc(e)}</span>
                )}
              </li>
            ))}
            {endpoints.length > shown.length && (
              <li className="font-mono text-[9.5px] text-muted/60">
                +{endpoints.length - shown.length} more endpoints…
              </li>
            )}
          </ul>
        </div>
      )}
    </Panel>
  );
}
