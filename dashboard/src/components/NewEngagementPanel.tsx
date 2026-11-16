"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { btnAccent, btnGhost, cx, Dot, inputCls, Micro, Panel, PanelHead, Toggle } from "./Bits";
import { api, errMessage } from "@/lib/api";
import type { EngagementForm, PreflightResult } from "@/lib/types";

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[9.5px] font-medium uppercase tracking-[0.18em] text-muted">
        {label}
      </span>
      {children}
      {hint && <span className="mt-1 block text-[10px] leading-snug text-muted/60">{hint}</span>}
    </label>
  );
}

function inDays(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}

/**
 * New engagement from a client URL. The server derives the scope from exactly the
 * hosts/ports typed here; "Check" previews it and sends one GET per URL.
 */
export function NewEngagementPanel({ className }: { className?: string }) {
  const router = useRouter();
  const [client, setClient] = useState("");
  const [targets, setTargets] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [ticket, setTicket] = useState("");
  const [ends, setEnds] = useState(inDays(7));
  const [objective, setObjective] = useState("");
  const [internal, setInternal] = useState(false);
  const [sandbox, setSandbox] = useState(true);
  const [multiAgent, setMultiAgent] = useState(true);
  const [rps, setRps] = useState("3");
  const [maxSteps, setMaxSteps] = useState("40");
  const [attest, setAttest] = useState(false);
  const [check, setCheck] = useState<PreflightResult | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState<"" | "check" | "launch">("");

  const form = (): EngagementForm => ({
    client: client.trim(),
    targets: targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean),
    authorized_by: authorizedBy.trim(),
    ticket: ticket.trim(),
    ends,
    objective: objective.trim(),
    allow_private_ranges: internal,
    sandbox,
    max_requests_per_second: Number(rps) || 3,
    multi_agent: multiAgent,
    max_steps: Number(maxSteps) || 40,
  });

  const runCheck = async () => {
    setBusy("check");
    setErrors([]);
    try {
      setCheck(await api.checkEngagement({ ...form(), probe: true }));
    } catch (err) {
      setErrors([errMessage(err)]);
    } finally {
      setBusy("");
    }
  };

  const launch = async (e: FormEvent) => {
    e.preventDefault();
    const errs: string[] = [];
    if (!objective.trim()) errs.push("objective is required");
    if (!attest) errs.push("confirm you hold written authorization for these targets");
    if (!check?.ok) errs.push("run Check first and fix anything it reports");
    setErrors(errs);
    if (errs.length) return;
    setBusy("launch");
    try {
      const res = await api.launchEngagement({ ...form(), confirm_authorized: true });
      router.push(`/runs?id=${encodeURIComponent(res.run_id)}`);
    } catch (err) {
      setErrors([errMessage(err)]);
      setBusy("");
    }
  };

  // Any edit invalidates the last check, so a launch always matches what was checked.
  const edit = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setCheck(null);
  };

  return (
    <Panel className={className}>
      <PanelHead
        label="NEW ENGAGEMENT"
        right={<span className="font-mono text-[9px] tracking-[0.14em] text-muted/60">TARGET URL</span>}
      />
      <form onSubmit={launch} noValidate className="space-y-3 px-3 py-3">
        <Field label="Client">
          <input className={inputCls} value={client} onChange={(e) => edit(setClient)(e.target.value)}
            placeholder="Acme Corp" autoComplete="off" />
        </Field>

        <Field label="Target URLs"
          hint="One per line. Scope = exactly these hosts and ports; no subdomains or wildcards.">
          <textarea className={cx(inputCls, "min-h-[64px] resize-y leading-relaxed")} value={targets}
            onChange={(e) => edit(setTargets)(e.target.value)} spellCheck={false}
            placeholder={"https://app.acme.com\nhttps://api.acme.com/v1"} />
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Authorized by" hint="Who signed the authorization.">
            <input className={inputCls} value={authorizedBy}
              onChange={(e) => edit(setAuthorizedBy)(e.target.value)} placeholder="Jane Doe, CISO" />
          </Field>
          <Field label="Authorization ref" hint="SOW, contract or bug-bounty URL.">
            <input className={inputCls} value={ticket} onChange={(e) => edit(setTicket)(e.target.value)}
              placeholder="SOW-2026-114" />
          </Field>
          <Field label="Window ends">
            <input className={inputCls} type="date" value={ends} min={inDays(0)} max={inDays(90)}
              onChange={(e) => edit(setEnds)(e.target.value)} />
          </Field>
          <Field label="Requests / sec">
            <input className={inputCls} type="number" min={0.5} max={20} step={0.5} value={rps}
              onChange={(e) => edit(setRps)(e.target.value)} />
          </Field>
        </div>

        <Field label="Objective" hint="What to prove. Credentials for test accounts can go here.">
          <textarea className={cx(inputCls, "min-h-[64px] resize-y leading-relaxed")} value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="Find authorization flaws between tenants; test accounts alice/… and bob/…" />
        </Field>

        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-edge/60 pt-3">
          <Toggle checked={sandbox} onChange={edit(setSandbox)} label="kali sandbox" />
          <Toggle checked={multiAgent} onChange={setMultiAgent} label="multi agent" />
          <Toggle checked={internal} onChange={edit(setInternal)} label="internal / private ranges" />
          <label className="flex items-center gap-2 font-mono text-[10px] text-muted">
            steps
            <input className={cx(inputCls, "w-16 py-1")} type="number" min={1} max={1000}
              value={maxSteps} onChange={(e) => setMaxSteps(e.target.value)} />
          </label>
        </div>

        <button type="button" onClick={runCheck} disabled={busy !== ""} className={cx(btnGhost, "w-full py-2")}>
          {busy === "check" ? "CHECKING…" : "CHECK TARGETS"}
        </button>

        {check && <CheckResult result={check} />}

        <label className="flex items-start gap-2 text-[11px] leading-snug text-muted">
          <input type="checkbox" className="mt-0.5" checked={attest} onChange={(e) => setAttest(e.target.checked)} />
          I hold written authorization from the client to test exactly these targets in this window.
        </label>

        {errors.length > 0 && (
          <ul className="space-y-1 rounded-md border border-accent/40 bg-accent/10 px-2.5 py-2">
            {errors.map((err, i) => (
              <li key={i} className="font-mono text-[11px] leading-snug text-accent">{err}</li>
            ))}
          </ul>
        )}

        <button type="submit" disabled={busy !== "" || !check?.ok || !attest}
          className={cx(btnAccent, "w-full py-2", "hover:bg-accent/25")}>
          {busy === "launch" ? "LAUNCHING…" : "START ENGAGEMENT"}
        </button>
      </form>
    </Panel>
  );
}

function CheckResult({ result }: { result: PreflightResult }) {
  return (
    <div className="space-y-2 rounded-md border border-edge bg-bg/60 px-2.5 py-2">
      <div className="flex items-center gap-2">
        <Dot tone={result.ok ? "ok" : "accent"} />
        <Micro>{result.ok ? "READY TO ARM" : "NOT READY"}</Micro>
      </div>
      {result.errors.map((e, i) => (
        <p key={i} className="font-mono text-[11px] leading-snug text-accent">{e}</p>
      ))}
      {result.scope && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-[10.5px]">
          <dt className="text-muted">hosts</dt>
          <dd className="break-all text-ink">{result.scope.allowed_hosts.join(", ")}</dd>
          <dt className="text-muted">ports</dt>
          <dd className="text-ink">{result.scope.allowed_ports.join(", ")}</dd>
          <dt className="text-muted">schemes</dt>
          <dd className="text-ink">{result.scope.allowed_schemes.join(", ")}</dd>
        </dl>
      )}
      {result.targets.map((t) => (
        <div key={t.url} className="border-t border-edge/60 pt-1.5 font-mono text-[10.5px] leading-snug">
          <div className="flex items-center gap-2">
            <Dot tone={t.in_scope && t.reachable?.ok ? "ok" : t.in_scope ? "warn" : "accent"} />
            <span className="break-all text-ink">{t.url}</span>
          </div>
          {t.ips.length > 0 && <div className="pl-4 text-muted">→ {t.ips.join(", ")}</div>}
          {t.error && <div className="pl-4 text-accent">{t.error}</div>}
          {t.reachable && (
            <div className="pl-4 text-muted">
              {t.reachable.ok
                ? `HTTP ${t.reachable.status}${t.reachable.server ? ` · ${t.reachable.server}` : ""}` +
                  `${t.reachable.title ? ` · “${t.reachable.title}”` : ""}` +
                  `${t.reachable.location ? ` · → ${t.reachable.location}` : ""}` +
                  ` · ${t.reachable.elapsed_ms} ms`
                : `unreachable: ${t.reachable.error}`}
            </div>
          )}
        </div>
      ))}
      {result.warnings.map((w, i) => (
        <p key={i} className="text-[10.5px] leading-snug text-warn">{w}</p>
      ))}
    </div>
  );
}
