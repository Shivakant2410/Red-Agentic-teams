"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  btnAccent,
  cx,
  Dot,
  IconChevron,
  inputCls,
  Micro,
  Panel,
  Toggle,
} from "./Bits";
import { api, errMessage } from "@/lib/api";
import type {
  LaunchAuthorization,
  LlmPreflightResult,
  MissionPlanTask,
  OllamaStatus,
} from "@/lib/types";

/**
 * Provider kinds the engine understands (mirrors server LLM_PROVIDER_SHORTCUTS
 * / redteam/llm/providers.py ProviderConfig.resolved()). Ollama is the DEFAULT:
 * the product must work without any hosted API key. "" = engine default.
 */
const PROVIDERS: { kind: string; label: string; keyHint: string }[] = [
  { kind: "ollama", label: "Ollama (local, no key)", keyHint: "" },
  { kind: "", label: "engine default (engagement yaml)", keyHint: "" },
  { kind: "openai", label: "OpenAI", keyHint: "OPENAI_API_KEY" },
  { kind: "zai", label: "Z.ai (GLM)", keyHint: "ZAI_API_KEY" },
  { kind: "gemini", label: "Gemini", keyHint: "GEMINI_API_KEY" },
  { kind: "openrouter", label: "OpenRouter", keyHint: "OPENROUTER_API_KEY" },
  { kind: "groq", label: "Groq", keyHint: "GROQ_API_KEY" },
  { kind: "anthropic", label: "Anthropic", keyHint: "ANTHROPIC_API_KEY" },
];

/** Fallback suggestions when an endpoint serves no catalog — the field stays
 *  free-text; real discovered ids always win (Ollama auto-connect merges them). */
const MODEL_PRESETS: Record<string, string[]> = {
  ollama: ["qwen2.5:7b-instruct", "llama3.2:latest", "llama3.1:8b", "mistral-nemo:latest"],
  openai: ["gpt-sol", "gpt-5.2", "gpt-5.1", "gpt-4o"],
  zai: ["glm-5.3", "glm-5.2", "glm-4.6", "glm-4.5-air"],
  gemini: ["gemini-argon", "gemini-hydrogen", "gemini-2.5-pro", "gemini-2.5-flash"],
  openrouter: ["z-ai/glm-4.6", "openai/gpt-5.1", "anthropic/claude-sonnet-4.5"],
};

/** The two execution drivers, with the operator-facing difference spelled out. */
const MODES: { id: "classic" | "mission"; label: string; hint: string }[] = [
  {
    id: "classic",
    label: "Classic",
    hint: "Autonomous orchestrator swarm: recon → exploit → verify → access → logic rounds driven by the existing Orchestrator.",
  },
  {
    id: "mission",
    label: "Adaptive mission",
    hint: "Mission coordination driver: claims tasks from the live AttackTree frontier, dispatches specialists, verifies independently, replans between rounds.",
  },
];

const INTENSITIES: { id: "low" | "standard" | "high"; hint: string }[] = [
  { id: "low", hint: "≤0.5 req/s, ≤200 requests total — gentle probing." },
  { id: "standard", hint: "≤3 req/s, ≤2000 requests total — recommended." },
  { id: "high", hint: "≤8 req/s, ≤5000 requests total — still bounded, never scanner-grade." },
];

function todayIso(offsetDays = 0): string {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

/** Light client-side URL check — the SERVER is the authority (it parses,
 *  normalizes and fail-closes); this only gives instant feedback. */
function clientUrlHint(url: string): string {
  const t = url.trim();
  if (!t) return "";
  if (!/^https?:\/\//i.test(t)) {
    return "Include the scheme — e.g. https://demo.testfire.net (or http://127.0.0.1:8901 for a local lab).";
  }
  return "";
}

function Field({
  label,
  children,
  hint,
  className,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
  className?: string;
}) {
  return (
    <label className={cx("block", className)}>
      <span className="mb-1 block text-[9.5px] font-medium uppercase tracking-[0.18em] text-muted">
        {label}
      </span>
      {children}
      {hint && (
        <span className="mt-1 block text-[10px] leading-snug text-muted/60">
          {hint}
        </span>
      )}
    </label>
  );
}

/**
 * URL-first launch panel (Builder 04). The operator enters the authorized
 * target URL — never a server filesystem path. The backend (POST /api/launch)
 * parses and normalizes the URL, enforces fail-closed authorization, builds
 * the internal RoE, validates it with the existing loader, and arms the SAME
 * pipeline as /api/runs (classic) and /api/missions (mission).
 *
 * Ollama auto-connect: the panel probes the configured Ollama endpoint for
 * real (a URL alone is never "connected"), lists INSTALLED models, selects a
 * usable one, and runs tool-call preflight — discovery is never proof of
 * tool-calling capability.
 */
export function LaunchRunPanel({ className }: { className?: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(true);
  const [mode, setMode] = useState<"classic" | "mission">("classic");
  const [targetUrl, setTargetUrl] = useState("");
  const [objective, setObjective] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [ticket, setTicket] = useState("");
  const [starts, setStarts] = useState(todayIso(-1));
  const [ends, setEnds] = useState(todayIso(7));
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [excludedHosts, setExcludedHosts] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [intensity, setIntensity] = useState<"low" | "standard" | "high">("standard");
  const [maxSteps, setMaxSteps] = useState("40");
  const [maxRunSeconds, setMaxRunSeconds] = useState("");
  const [maxLlmTokens, setMaxLlmTokens] = useState("");
  const [sourceDir, setSourceDir] = useState("");
  const [multiAgent, setMultiAgent] = useState(true);
  const [yesToAll, setYesToAll] = useState(false);
  const [assetFeed, setAssetFeed] = useState("");
  const [planText, setPlanText] = useState("");
  const [planOpen, setPlanOpen] = useState(false);

  // model provider — Ollama by default (works with zero hosted API keys)
  const [llmProvider, setLlmProvider] = useState("ollama");
  const [llmModel, setLlmModel] = useState("");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [ollamaBaseUrl, setOllamaBaseUrl] = useState("");
  const [ollama, setOllama] = useState<OllamaStatus | null>(null);
  const [ollamaProbing, setOllamaProbing] = useState(false);
  const [preflight, setPreflight] = useState<LlmPreflightResult | null>(null);
  const [preflightPending, setPreflightPending] = useState(false);
  const [discovered, setDiscovered] = useState<string[]>([]);
  const autoPreflightDone = useRef(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [pending, setPending] = useState(false);

  /* ── Ollama auto-connect: REAL probe, never a URL-only claim ───────────── */
  const refreshOllama = (baseUrl: string) => {
    setOllamaProbing(true);
    api
      .ollamaStatus(baseUrl.trim())
      .then((s) => setOllama(s))
      .catch((e) =>
        setOllama({
          provider: "ollama",
          base_url: baseUrl.trim() || "http://127.0.0.1:11434",
          connected: false,
          state: "error",
          version: "",
          models: [],
          default_model: "",
          message: "Ollama is not running. Start Ollama and retry.",
          detail: errMessage(e),
        }),
      )
      .finally(() => setOllamaProbing(false));
  };

  useEffect(() => {
    if (llmProvider !== "ollama") {
      setOllama(null);
      setDiscovered([]);
      return;
    }
    refreshOllama(ollamaBaseUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [llmProvider, ollamaBaseUrl]);

  /* On a successful probe: populate the selector with INSTALLED models and
     pick a usable default. Then run preflight ONCE — discovery is not proof
     of tool-calling capability. */
  useEffect(() => {
    if (llmProvider !== "ollama" || !ollama || !ollama.connected) return;
    setDiscovered(ollama.models);
    if (!llmModel.trim() && ollama.default_model) {
      setLlmModel(ollama.default_model);
    }
    if (!autoPreflightDone.current && (llmModel.trim() || ollama.default_model)) {
      autoPreflightDone.current = true;
      runPreflight(llmModel.trim() || ollama.default_model);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ollama, llmProvider]);

  const runPreflight = (modelOverride?: string) => {
    setPreflightPending(true);
    setPreflight(null);
    api
      .preflightLlm({
        provider: llmProvider,
        ...(modelOverride ?? llmModel.trim() ? { model: (modelOverride ?? llmModel.trim()) } : {}),
        ...(llmApiKey ? { api_key: llmApiKey } : {}),
        ...(llmProvider === "ollama" && ollamaBaseUrl.trim()
          ? { base_url: ollamaBaseUrl.trim() }
          : {}),
      })
      .then(setPreflight)
      .catch((err) => setErrors([`preflight: ${errMessage(err)}`]))
      .finally(() => setPreflightPending(false));
  };

  /* ── launch gating (honest, actionable) ────────────────────────────────── */
  const ollamaNotReady =
    llmProvider === "ollama" && ollama != null && !ollama.connected;
  const ollamaNoModels =
    llmProvider === "ollama" && ollama?.connected === true && ollama.models.length === 0;
  const preflightFailed = preflight != null && preflightPending === false && !preflight.ok;

  const launchBlockers = useMemo(() => {
    const msgs: string[] = [];
    if (ollamaNotReady) msgs.push(ollama?.message ?? "Ollama is not running. Start Ollama and retry.");
    if (ollamaNoModels)
      msgs.push("Ollama is running, but no models are installed. Pull a supported model first.");
    if (preflightFailed)
      msgs.push("The selected model did not pass tool-calling preflight. Select another model.");
    return msgs;
  }, [ollamaNotReady, ollamaNoModels, preflightFailed, ollama]);

  /* ── live scope summary (server re-validates everything fail-closed) ───── */
  const parsedTarget = useMemo(() => {
    const t = targetUrl.trim();
    const m = /^https?:\/\//i.exec(t);
    if (!m) return null;
    try {
      const u = new URL(t);
      if (!u.hostname) return null;
      return {
        scheme: u.protocol.replace(":", "").toLowerCase(),
        host: u.hostname.toLowerCase(),
        port: u.port
          ? Number(u.port)
          : u.protocol.toLowerCase() === "https:"
            ? 443
            : 80,
      };
    } catch {
      return null;
    }
  }, [targetUrl]);

  const urlHint = clientUrlHint(targetUrl);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errs: string[] = [];
    if (!targetUrl.trim()) errs.push("target URL is required — enter the web application you are authorized to test");
    else if (urlHint) errs.push(urlHint);
    if (!objective.trim()) errs.push("objective is required");
    if (!authorizedBy.trim()) errs.push("authorized_by is required — record who authorized this assessment");
    if (!ticket.trim()) errs.push("ticket is required — reference the signed authorization document");
    if (!confirmed) errs.push("authorization confirmation is required — check the confirmation box to attest you are authorized");
    const steps = Number(maxSteps);
    if (!Number.isInteger(steps) || steps < 1 || steps > 1000) {
      errs.push("max_steps must be an integer between 1 and 1000");
    }
    // An explicit mission plan is strictly opt-in AND must parse as a JSON
    // array of tasks — a typo must fail HERE, not become a malformed plan file.
    let plan: MissionPlanTask[] | undefined;
    if (mode === "mission" && planText.trim()) {
      try {
        const parsed: unknown = JSON.parse(planText);
        if (!Array.isArray(parsed)) throw new Error("not an array");
        plan = parsed as MissionPlanTask[];
      } catch {
        errs.push("explicit mission plan must be a JSON array of task objects (leave empty for the dynamic AttackTree frontier)");
      }
    }
    setErrors(errs);
    if (errs.length > 0 || launchBlockers.length > 0) return;

    const authorization: LaunchAuthorization = {
      confirmed,
      authorized_by: authorizedBy.trim(),
      ticket: ticket.trim(),
      starts: starts.trim() || todayIso(-1),
      ends: ends.trim() || todayIso(7),
      allow_private_ranges: allowPrivate,
      ...(excludedHosts.trim()
        ? { excluded_hosts: excludedHosts.split(",").map((h) => h.trim()).filter(Boolean) }
        : {}),
    };
    const llm = llmProvider
      ? {
          provider: llmProvider,
          ...(llmModel.trim() ? { model: llmModel.trim() } : {}),
          ...(llmApiKey ? { api_key: llmApiKey } : {}),
          ...(llmProvider === "ollama" && ollamaBaseUrl.trim()
            ? { base_url: ollamaBaseUrl.trim() }
            : {}),
        }
      : undefined;

    setPending(true);
    try {
      const res = await api.launchFromUrl({
        target_url: targetUrl.trim(),
        objective: objective.trim(),
        mode,
        authorization,
        intensity,
        max_steps: steps,
        ...(Number(maxRunSeconds) > 0 ? { max_run_seconds: Number(maxRunSeconds) } : {}),
        ...(Number(maxLlmTokens) > 0 ? { max_llm_tokens: Number(maxLlmTokens) } : {}),
        multi_agent: multiAgent,
        yes_to_all: yesToAll,
        ...(mode === "classic" && sourceDir.trim() ? { source_dir: sourceDir.trim() } : {}),
        ...(mode === "mission" && assetFeed.trim() ? { asset_feed: assetFeed.trim() } : {}),
        ...(plan ? { plan } : {}),
        ...(llm ? { llm } : {}),
      });
      // Hand over to the run-detail page (mission_id == run_id today; the run
      // id is the one the detail route tracks).
      window.dispatchEvent(new Event("run:launched"));
      router.push(`/runs?id=${encodeURIComponent(res.run_id)}`);
    } catch (err) {
      setErrors([errMessage(err)]);
      setPending(false);
    }
  };

  const activeMode = MODES.find((m) => m.id === mode)!;
  const activeIntensity = INTENSITIES.find((i) => i.id === intensity)!;
  const providerMeta = PROVIDERS.find((p) => p.kind === llmProvider);

  return (
    <Panel className={cx("self-start", className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 px-3 py-2 text-left focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70"
      >
        <IconChevron
          className={cx(
            "h-3.5 w-3.5 shrink-0 text-muted transition-transform",
            !open && "rotate-180",
          )}
        />
        <Micro>LAUNCH ASSESSMENT</Micro>
        <span className="ml-auto font-mono text-[9px] tracking-[0.14em] text-muted/60">
          POST /API/LAUNCH
        </span>
      </button>

      {open && (
        <form onSubmit={submit} noValidate className="space-y-3 border-t border-edge px-3 py-3">
          {/* execution mode */}
          <div className="space-y-1.5">
            <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label="execution mode">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  role="radio"
                  aria-checked={mode === m.id}
                  onClick={() => setMode(m.id)}
                  className={cx(
                    "rounded-md border px-2 py-1.5 text-center font-mono text-[10px] uppercase tracking-[0.14em] transition-colors",
                    mode === m.id
                      ? "border-info/60 bg-info/15 text-ink"
                      : "border-edge bg-panel2/40 text-muted hover:border-muted/40",
                  )}
                >
                  {m.label}
                </button>
              ))}
            </div>
            <p className="text-[10px] leading-snug text-muted/70">{activeMode.hint}</p>
          </div>

          {/* target */}
          <Field
            label="target url"
            hint="The web application you are authorized to assess. Everything else stays out of scope."
          >
            <input
              className={inputCls}
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://demo.testfire.net"
              spellCheck={false}
              autoComplete="off"
              required
            />
          </Field>
          {urlHint && (
            <p className="font-mono text-[10px] leading-snug text-warn">{urlHint}</p>
          )}

          <Field
            label="objective"
            hint="What the assessment should accomplish. Scored continuously."
          >
            <textarea
              className={cx(inputCls, "min-h-[64px] resize-y leading-relaxed")}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Assess the authorized web application for security weaknesses and provide independently verified findings."
              spellCheck={false}
              required
            />
          </Field>

          {/* authorization — a checkbox alone is NOT proof */}
          <div className="space-y-2 rounded-md border border-edge/60 bg-panel2/30 px-2.5 py-2.5">
            <div className="flex items-center justify-between">
              <Micro>AUTHORIZATION</Micro>
              <span className="font-mono text-[9px] tracking-[0.14em] text-muted/50">
                FAIL-CLOSED
              </span>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="authorized by" hint="Who authorized this assessment.">
                <input
                  className={inputCls}
                  value={authorizedBy}
                  onChange={(e) => setAuthorizedBy(e.target.value)}
                  placeholder="name or authority"
                  autoComplete="off"
                />
              </Field>
              <Field label="ticket" hint="Signed authorization reference (SOW, bounty scope URL, CR).">
                <input
                  className={inputCls}
                  value={ticket}
                  onChange={(e) => setTicket(e.target.value)}
                  placeholder="ROE-2026-001"
                  autoComplete="off"
                />
              </Field>
              <Field label="window start">
                <input
                  className={inputCls}
                  type="date"
                  value={starts}
                  onChange={(e) => setStarts(e.target.value)}
                />
              </Field>
              <Field label="window end">
                <input
                  className={inputCls}
                  type="date"
                  value={ends}
                  onChange={(e) => setEnds(e.target.value)}
                />
              </Field>
            </div>
            <Field
              label="excluded hosts (optional)"
              hint="Comma-separated carve-outs that always win over the allowlist."
            >
              <input
                className={inputCls}
                value={excludedHosts}
                onChange={(e) => setExcludedHosts(e.target.value)}
                placeholder="(none)"
                spellCheck={false}
                autoComplete="off"
              />
            </Field>
            <Toggle
              checked={allowPrivate}
              onChange={setAllowPrivate}
              label="local / private lab target"
            />
            <label className="flex items-start gap-2 text-[11px] leading-snug text-muted">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 accent-[var(--accent)]"
                aria-label="confirm authorization"
              />
              <span>
                I confirm I am authorized to test this target under the recorded
                authorization. Launching is refused without this confirmation.
              </span>
            </label>
          </div>

          {/* scope summary — the exact scope before launch */}
          <div className="space-y-1 rounded-md border border-info/30 bg-info/5 px-2.5 py-2">
            <Micro>SCOPE AT LAUNCH</Micro>
            {parsedTarget ? (
              <ul className="space-y-0.5 font-mono text-[10.5px] leading-snug text-muted">
                <li>
                  target: <span className="text-ink">{parsedTarget.scheme}://{parsedTarget.host}:{parsedTarget.port}</span>
                </li>
                <li>in scope: this host and port only · window {starts} → {ends} · intensity {intensity}</li>
                <li>out of scope: every other host and port — redirects and discovered hosts are re-checked against this scope before each request</li>
                {allowPrivate && <li>private/loopback ranges: explicitly authorized for this local-lab target</li>}
              </ul>
            ) : (
              <p className="font-mono text-[10.5px] leading-snug text-muted/70">
                enter the target URL to preview the exact scope
              </p>
            )}
          </div>

          {/* budget */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="intensity" hint={activeIntensity.hint}>
              <select
                className={inputCls}
                value={intensity}
                onChange={(e) => setIntensity(e.target.value as typeof intensity)}
              >
                {INTENSITIES.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.id}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="max_steps">
              <input
                className={inputCls}
                type="number"
                min={1}
                max={1000}
                step={1}
                value={maxSteps}
                onChange={(e) => setMaxSteps(e.target.value)}
              />
            </Field>
            <Field label="max run seconds (optional)" hint="0 = unlimited wall clock.">
              <input
                className={inputCls}
                type="number"
                min={0}
                step={60}
                value={maxRunSeconds}
                onChange={(e) => setMaxRunSeconds(e.target.value)}
                placeholder="(unlimited)"
              />
            </Field>
            <Field label="max llm tokens (optional)" hint="0 = unlimited tokens.">
              <input
                className={inputCls}
                type="number"
                min={0}
                step={10000}
                value={maxLlmTokens}
                onChange={(e) => setMaxLlmTokens(e.target.value)}
                placeholder="(unlimited)"
              />
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-edge/60 pt-3">
            {mode === "classic" && (
              <Toggle checked={multiAgent} onChange={setMultiAgent} label="multi_agent" />
            )}
            <Toggle checked={yesToAll} onChange={setYesToAll} label="yes_to_all" />
          </div>

          {mode === "classic" && (
            <Field label="source_dir (optional)" hint="Local source code for static recon.">
              <input
                className={inputCls}
                value={sourceDir}
                onChange={(e) => setSourceDir(e.target.value)}
                placeholder="(optional)"
                spellCheck={false}
                autoComplete="off"
              />
            </Field>
          )}

          {mode === "mission" && (
            <div className="space-y-1.5">
              <Field
                label="asset_feed (optional)"
                hint="Optional CSV/JSON/JSONL asset feed — strictly intersected with the RoE."
              >
                <input
                  className={inputCls}
                  value={assetFeed}
                  onChange={(e) => setAssetFeed(e.target.value)}
                  placeholder="(optional)"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>
              <div className="rounded-md border border-edge/60 bg-panel2/30 px-2.5 py-2">
                <button
                  type="button"
                  onClick={() => setPlanOpen((o) => !o)}
                  aria-expanded={planOpen}
                  className="flex w-full items-center gap-2 text-left"
                >
                  <IconChevron
                    className={cx(
                      "h-3 w-3 shrink-0 text-muted transition-transform",
                      !planOpen && "rotate-180",
                    )}
                  />
                  <span className="font-mono text-[9.5px] uppercase tracking-[0.18em] text-muted">
                    explicit plan (optional)
                  </span>
                  <span className="ml-auto font-mono text-[9px] text-muted/50">
                    {planText.trim() ? "STATIC OVERRIDE" : "DYNAMIC FRONTIER"}
                  </span>
                </button>
                {planOpen && (
                  <Field
                    label="plan (json array)"
                    hint="Leave EMPTY for the default: live AttackTree frontier selection + replanning."
                  >
                    <textarea
                      className={cx(inputCls, "min-h-[64px] resize-y font-mono text-[10.5px] leading-relaxed")}
                      value={planText}
                      onChange={(e) => setPlanText(e.target.value)}
                      placeholder={'[{"technique": "sqli", "target": "/orders", "objective": "prove injection"}]'}
                      spellCheck={false}
                    />
                  </Field>
                )}
              </div>
            </div>
          )}

          {/* model provider — Ollama default + auto-connect */}
          <div className="space-y-3 border-t border-edge/60 pt-3">
            <div className="flex items-center justify-between">
              <Micro>MODEL PROVIDER</Micro>
              <div className="flex items-center gap-2">
                {llmProvider && (
                  <button
                    type="button"
                    onClick={() => runPreflight()}
                    disabled={preflightPending}
                    className={cx(
                      "rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] transition-colors",
                      preflightPending
                        ? "border-edge text-muted/60"
                        : "border-info/50 text-info hover:bg-info/10",
                    )}
                  >
                    {preflightPending ? "CHECKING…" : "PREFLIGHT"}
                  </button>
                )}
                {llmProvider === "ollama" && (
                  <button
                    type="button"
                    onClick={() => refreshOllama(ollamaBaseUrl)}
                    disabled={ollamaProbing}
                    className={cx(
                      "rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] transition-colors",
                      ollamaProbing
                        ? "border-edge text-muted/60"
                        : "border-edge text-muted hover:border-muted/50 hover:text-ink",
                    )}
                  >
                    {ollamaProbing ? "PROBING…" : "RE-PROBE"}
                  </button>
                )}
              </div>
            </div>

            {/* Ollama connection status — exact, honest states */}
            {llmProvider === "ollama" && (
              <div
                className={cx(
                  "flex items-start gap-2 rounded-md border px-2.5 py-2",
                  ollama?.connected && ollama.models.length > 0
                    ? "border-ok/40 bg-ok/10"
                    : ollama?.connected
                      ? "border-warn/40 bg-warn/10"
                      : "border-accent/40 bg-accent/10",
                )}
                role="status"
              >
                <Dot
                  tone={ollama?.connected && ollama.models.length > 0 ? "ok" : ollama?.connected ? "warn" : "accent"}
                  pulse={ollamaProbing}
                />
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-[11px] leading-snug text-ink">
                    {ollamaProbing && !ollama ? "checking Ollama…" : ollama?.message ?? "checking Ollama…"}
                  </p>
                  {ollama?.connected && ollama.version && (
                    <p className="mt-0.5 font-mono text-[9.5px] text-muted/70">
                      v{ollama.version} · {ollama.base_url}
                    </p>
                  )}
                  {!ollama?.connected && ollama?.detail && (
                    <p className="mt-0.5 break-all font-mono text-[9.5px] text-muted/70">
                      {ollama.detail}
                    </p>
                  )}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field
                label="provider"
                hint="Ollama (local, no key) is the default. Change it any time."
              >
                <select
                  className={inputCls}
                  value={llmProvider}
                  onChange={(e) => {
                    setLlmProvider(e.target.value);
                    setLlmModel("");
                    setPreflight(null);
                    setDiscovered([]);
                    autoPreflightDone.current = false;
                  }}
                >
                  {PROVIDERS.map((p) => (
                    <option key={p.kind} value={p.kind}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="model"
                hint={
                  llmProvider === "ollama" && discovered.length > 0
                    ? "Installed models discovered from the endpoint — pick one."
                    : llmProvider
                      ? "Pins this run's rotation to the model id."
                      : "Pick a provider to select a model."
                }
              >
                <input
                  className={inputCls}
                  value={llmModel}
                  onChange={(e) => setLlmModel(e.target.value)}
                  placeholder="(provider default rotation)"
                  list={llmProvider ? `model-presets-${llmProvider}` : undefined}
                  spellCheck={false}
                  autoComplete="off"
                  disabled={!llmProvider}
                />
                {llmProvider && (
                  <datalist id={`model-presets-${llmProvider}`}>
                    {Array.from(
                      new Set([...(MODEL_PRESETS[llmProvider] ?? []), ...discovered]),
                    ).map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                )}
                {llmProvider === "ollama" && discovered.length > 0 && (
                  <span className="mt-1 block text-[10px] leading-snug text-muted/60">
                    {discovered.length} installed model(s) discovered — discovery does not
                    prove tool-calling; the preflight does.
                  </span>
                )}
              </Field>
            </div>

            {preflight && (
              <ul className="space-y-1 rounded-md border border-edge/60 bg-panel2/30 px-2.5 py-2">
                {preflight.checks.map((c, i) => (
                  <li key={i} className="flex gap-2 font-mono text-[10.5px] leading-snug">
                    <span className={c.ok ? "text-ok" : "text-accent"}>
                      {c.ok ? "PASS" : "FAIL"}
                    </span>
                    <span className="text-muted">{c.check}</span>
                    <span className="min-w-0 flex-1 text-muted/80">{c.detail}</span>
                  </li>
                ))}
                <li className="flex gap-2 pt-0.5 font-mono text-[10px] text-muted/60">
                  <span>
                    agent server → {preflight.base_url} · {preflight.latency_ms} ms
                  </span>
                  <span className="ml-auto">
                    {preflight.ok
                      ? "READY — this model can drive tools"
                      : "NOT READY — fix the failing checks before launching"}
                  </span>
                </li>
              </ul>
            )}

            {providerMeta?.keyHint ? (
              <Field
                label="api key"
                hint={`Run-scoped credential for this run (${providerMeta.keyHint} channel) — held in memory server-side, never written to disk or the process env.`}
              >
                <input
                  className={inputCls}
                  type="password"
                  value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)}
                  placeholder="(or pre-set the env var yourself)"
                  autoComplete="off"
                />
              </Field>
            ) : null}

            {llmProvider === "ollama" && (
              <Field
                label="ollama endpoint (optional)"
                hint="Default http://127.0.0.1:11434 — change for a remote Ollama host."
              >
                <input
                  className={inputCls}
                  value={ollamaBaseUrl}
                  onChange={(e) => setOllamaBaseUrl(e.target.value)}
                  placeholder="(http://127.0.0.1:11434)"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>
            )}
            {llmProvider && llmProvider !== "ollama" && (
              <Field
                label="base_url"
                hint="Override the endpoint (vLLM / LM Studio / a private proxy). Leave empty for the provider default."
              >
                <input
                  className={inputCls}
                  value={ollamaBaseUrl}
                  onChange={(e) => setOllamaBaseUrl(e.target.value)}
                  placeholder="(provider default)"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>
            )}
          </div>

          {launchBlockers.length > 0 && (
            <ul className="space-y-1 rounded-md border border-warn/40 bg-warn/10 px-2.5 py-2">
              {launchBlockers.map((msg, i) => (
                <li key={i} className="font-mono text-[11px] leading-snug text-warn">
                  {msg}
                </li>
              ))}
            </ul>
          )}

          {errors.length > 0 && (
            <ul className="space-y-1 rounded-md border border-accent/40 bg-accent/10 px-2.5 py-2">
              {errors.map((err, i) => (
                <li key={i} className="font-mono text-[11px] leading-snug text-accent">
                  {err}
                </li>
              ))}
            </ul>
          )}

          <button
            type="submit"
            disabled={pending || launchBlockers.length > 0}
            className={cx(btnAccent, "w-full py-2", "hover:bg-accent/25")}
            title={launchBlockers.length > 0 ? launchBlockers.join(" · ") : undefined}
          >
            {pending ? "LAUNCHING…" : mode === "classic" ? "LAUNCH RUN" : "LAUNCH MISSION"}
          </button>
        </form>
      )}
    </Panel>
  );
}
