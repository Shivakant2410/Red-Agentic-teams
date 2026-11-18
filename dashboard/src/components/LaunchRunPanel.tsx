"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import {
  btnAccent,
  cx,
  IconChevron,
  inputCls,
  Micro,
  Panel,
  PanelHead,
  Toggle,
} from "./Bits";
import { api, errMessage } from "@/lib/api";
import type { LlmOverride } from "@/lib/types";

/**
 * Provider kinds the engine understands (mirrors server LLM_PROVIDER_SHORTCUTS
 * / redteam/llm/providers.py ProviderConfig.resolved()). "" = no override —
 * the run uses whatever the engagement file itself configures.
 */
const PROVIDERS: { kind: string; label: string; keyHint: string }[] = [
  { kind: "", label: "engine default (engagement yaml)", keyHint: "" },
  { kind: "openai", label: "OpenAI", keyHint: "OPENAI_API_KEY" },
  { kind: "zai", label: "Z.ai (GLM)", keyHint: "ZAI_API_KEY" },
  { kind: "gemini", label: "Gemini", keyHint: "GEMINI_API_KEY" },
  { kind: "openrouter", label: "OpenRouter", keyHint: "OPENROUTER_API_KEY" },
  { kind: "ollama", label: "Ollama (local, no key)", keyHint: "" },
  { kind: "groq", label: "Groq", keyHint: "GROQ_API_KEY" },
  { kind: "anthropic", label: "Anthropic", keyHint: "ANTHROPIC_API_KEY" },
];

/** Preset suggestions per provider — the field stays free-text, any model id
 *  the backend serves can be typed (unknown ids degrade via the engine's
 *  rotation, they never crash the run). */
const MODEL_PRESETS: Record<string, string[]> = {
  openai: ["gpt-sol", "gpt-5.2", "gpt-5.1", "gpt-4o"],
  zai: ["glm-5.3", "glm-5.2", "glm-4.6", "glm-4.5-air"],
  gemini: ["gemini-argon", "gemini-hydrogen", "gemini-2.5-pro", "gemini-2.5-flash"],
  openrouter: ["z-ai/glm-4.6", "openai/gpt-5.1", "anthropic/claude-sonnet-4.5",
    "deepseek/deepseek-chat"],
  ollama: ["llama3.2", "qwen2.5", "mistral", "gemma2"],
};

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
 * Collapsible "Launch run" form → POST /api/runs.
 * On 202 the operator is redirected straight into mission control.
 */
export function LaunchRunPanel({ className }: { className?: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(true);
  const [engagementPath, setEngagementPath] = useState("");
  const [objective, setObjective] = useState("");
  const [sourceDir, setSourceDir] = useState("");
  const [maxSteps, setMaxSteps] = useState("40");
  const [multiAgent, setMultiAgent] = useState(true);
  const [yesToAll, setYesToAll] = useState(false);
  const [llmProvider, setLlmProvider] = useState("");
  const [llmModel, setLlmModel] = useState("");
  const [llmApiKey, setLlmApiKey] = useState("");
  const [llmBaseUrl, setLlmBaseUrl] = useState("");
  const [errors, setErrors] = useState<string[]>([]);
  const [pending, setPending] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const errs: string[] = [];
    if (!engagementPath.trim()) errs.push("engagement_path is required");
    if (!objective.trim()) errs.push("objective is required");
    const steps = Number(maxSteps);
    if (!Number.isInteger(steps) || steps < 1 || steps > 1000) {
      errs.push("max_steps must be an integer between 1 and 1000");
    }
    setErrors(errs);
    if (errs.length > 0) return;

    const body: Parameters<typeof api.launchRun>[0] = {
      engagement_path: engagementPath.trim(),
      objective: objective.trim(),
      multi_agent: multiAgent,
      max_steps: steps,
      source_dir: sourceDir.trim(),
      yes_to_all: yesToAll,
    };
    if (llmProvider) {
      const override: LlmOverride = { provider: llmProvider };
      if (llmModel.trim()) override.model = llmModel.trim();
      if (llmApiKey) override.api_key = llmApiKey;
      if (llmBaseUrl.trim()) override.base_url = llmBaseUrl.trim();
      body.llm = override;
    }

    setPending(true);
    try {
      const res = await api.launchRun(body);
      router.push(`/runs?id=${encodeURIComponent(res.run_id)}`);
    } catch (err) {
      setErrors([errMessage(err)]);
      setPending(false);
    }
  };

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
        <Micro>LAUNCH RUN</Micro>
        <span className="ml-auto font-mono text-[9px] tracking-[0.14em] text-muted/60">
          POST /API/RUNS
        </span>
      </button>

      {open && (
        <form onSubmit={submit} noValidate className="space-y-3 border-t border-edge px-3 py-3">
          <Field
            label="engagement_path"
            hint="Path to the engagement directory (YAML + scope) on the server host."
          >
            <input
              className={inputCls}
              value={engagementPath}
              onChange={(e) => setEngagementPath(e.target.value)}
              placeholder="/opt/engagements/acme-corp"
              spellCheck={false}
              autoComplete="off"
              required
            />
          </Field>

          <Field label="objective" hint="What the team should accomplish. Scored continuously.">
            <textarea
              className={cx(inputCls, "min-h-[76px] resize-y leading-relaxed")}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Retrieve the customer table from the staging web app and prove access to its admin console."
              spellCheck={false}
              required
            />
          </Field>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
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
            <Field label="source_dir" hint="Optional local source code for static recon.">
              <input
                className={inputCls}
                value={sourceDir}
                onChange={(e) => setSourceDir(e.target.value)}
                placeholder="(optional)"
                spellCheck={false}
                autoComplete="off"
              />
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-edge/60 pt-3">
            <Toggle checked={multiAgent} onChange={setMultiAgent} label="multi_agent" />
            <Toggle checked={yesToAll} onChange={setYesToAll} label="yes_to_all" />
          </div>

          <div className="space-y-3 border-t border-edge/60 pt-3">
            <div className="flex items-center justify-between">
              <Micro>MODEL PROVIDER</Micro>
              <span className="font-mono text-[9px] tracking-[0.14em] text-muted/60">
                LLM OVERRIDE
              </span>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field
                label="provider"
                hint="Which LLM backend the fleet runs on for this run."
              >
                <select
                  className={inputCls}
                  value={llmProvider}
                  onChange={(e) => {
                    setLlmProvider(e.target.value);
                    setLlmModel("");
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
                  llmProvider
                    ? "Pins this run's rotation to the model id (free text — presets are suggestions)."
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
                {llmProvider && MODEL_PRESETS[llmProvider] && (
                  <datalist id={`model-presets-${llmProvider}`}>
                    {MODEL_PRESETS[llmProvider].map((m) => (
                      <option key={m} value={m} />
                    ))}
                  </datalist>
                )}
              </Field>
            </div>
            {llmProvider && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {PROVIDERS.find((p) => p.kind === llmProvider)?.keyHint ? (
                  <Field
                    label="api key"
                    hint={`Goes to ${PROVIDERS.find((p) => p.kind === llmProvider)?.keyHint} in the server process for this run — never written to disk.`}
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
                <Field
                  label="base_url"
                  hint="Override the endpoint (vLLM / LM Studio / a private proxy). Leave empty for the provider default."
                >
                  <input
                    className={inputCls}
                    value={llmBaseUrl}
                    onChange={(e) => setLlmBaseUrl(e.target.value)}
                    placeholder="(provider default)"
                    spellCheck={false}
                    autoComplete="off"
                  />
                </Field>
              </div>
            )}
          </div>

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
            disabled={pending}
            className={cx(btnAccent, "w-full py-2", "hover:bg-accent/25")}
          >
            {pending ? "LAUNCHING…" : "LAUNCH RUN"}
          </button>
        </form>
      )}
    </Panel>
  );
}
