"use client";

import { useEffect, type ReactNode } from "react";

/* ── class join ─────────────────────────────────────────────────────────── */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

/* ── semantic tone system (all literals — Tailwind scans these) ──────────── */
export type Tone =
  | "accent"
  | "ok"
  | "warn"
  | "info"
  | "purple"
  | "cyan"
  | "orange"
  | "muted"
  | "ink";

export const toneFg: Record<Tone, string> = {
  accent: "text-accent",
  ok: "text-ok",
  warn: "text-warn",
  info: "text-info",
  purple: "text-purple",
  cyan: "text-cyan",
  orange: "text-orange",
  muted: "text-muted",
  ink: "text-ink",
};
export const toneBgSoft: Record<Tone, string> = {
  accent: "bg-accent/10",
  ok: "bg-ok/10",
  warn: "bg-warn/10",
  info: "bg-info/10",
  purple: "bg-purple/10",
  cyan: "bg-cyan/10",
  orange: "bg-orange/10",
  muted: "bg-muted/10",
  ink: "bg-ink/10",
};
export const toneBorderSoft: Record<Tone, string> = {
  accent: "border-accent/40",
  ok: "border-ok/40",
  warn: "border-warn/40",
  info: "border-info/40",
  purple: "border-purple/40",
  cyan: "border-cyan/40",
  orange: "border-orange/40",
  muted: "border-muted/30",
  ink: "border-ink/30",
};
export const toneBorderL: Record<Tone, string> = {
  accent: "border-l-accent",
  ok: "border-l-ok",
  warn: "border-l-warn",
  info: "border-l-info",
  purple: "border-l-purple",
  cyan: "border-l-cyan",
  orange: "border-l-orange",
  muted: "border-l-muted",
  ink: "border-l-ink",
};
export const toneDot: Record<Tone, string> = {
  accent: "bg-accent",
  ok: "bg-ok",
  warn: "bg-warn",
  info: "bg-info",
  purple: "bg-purple",
  cyan: "bg-cyan",
  orange: "bg-orange",
  muted: "bg-muted",
  ink: "bg-ink",
};

/* ── layout primitives ───────────────────────────────────────────────────── */
export function Micro({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cx(
        "text-[10px] font-medium uppercase tracking-[0.22em] text-muted",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function Panel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cx("rounded-lg border border-edge bg-panel", className)}
    >
      {children}
    </section>
  );
}

/** Panel header strip: micro label on the left, meta on the right. */
export function PanelHead({
  label,
  right,
  className,
}: {
  label: ReactNode;
  right?: ReactNode;
  className?: string;
}) {
  return (
    <header
      className={cx(
        "flex items-center gap-2.5 border-b border-edge px-3 py-2",
        className,
      )}
    >
      <Micro>{label}</Micro>
      <div className="ml-auto flex min-w-0 items-center gap-2">{right}</div>
    </header>
  );
}

/* ── atoms ───────────────────────────────────────────────────────────────── */
export function Dot({
  tone = "muted",
  pulse = false,
  className,
}: {
  tone?: Tone;
  pulse?: boolean;
  className?: string;
}) {
  return (
    <span
      aria-hidden
      className={cx(
        "inline-block h-[7px] w-[7px] shrink-0 rounded-full",
        toneDot[tone],
        toneFg[tone],
        pulse && "blip",
        className,
      )}
    />
  );
}

export function Chip({
  tone = "muted",
  children,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded border px-1.5 py-px font-mono text-[9.5px] uppercase tracking-[0.14em]",
        toneBorderSoft[tone],
        toneBgSoft[tone],
        toneFg[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

const ROLE_TONE: Record<string, Tone> = {
  recon: "info",
  exploit: "accent",
  access: "warn",
  logic: "purple",
  verify: "ok",
  single: "cyan",
  orchestrator: "ink",
};

export function RoleChip({ role }: { role?: string | null }) {
  const key = (role ?? "").toLowerCase();
  const tone = ROLE_TONE[key] ?? "muted";
  return <Chip tone={tone}>{role || "agent"}</Chip>;
}

const SEV_TONE: Record<string, Tone> = {
  critical: "accent",
  high: "orange",
  medium: "warn",
  low: "info",
  info: "muted",
};

export function severityTone(severity?: string | null): Tone {
  return SEV_TONE[(severity ?? "").toLowerCase()] ?? "muted";
}

export function SeverityChip({ severity }: { severity?: string | null }) {
  return <Chip tone={severityTone(severity)}>{severity || "info"}</Chip>;
}

export function ConfidenceChip({ confidence }: { confidence?: string | null }) {
  const key = (confidence ?? "").toLowerCase();
  if (key === "confirmed")
    return <Chip tone="ok">confirmed</Chip>;
  if (!key) return null;
  return <Chip tone="muted">{confidence}</Chip>;
}

/* ── buttons / inputs ────────────────────────────────────────────────────── */
export const btnBase =
  "inline-flex items-center justify-center gap-1.5 rounded-md border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] transition-colors disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70";

export const btnGhost = cx(
  btnBase,
  "border-edge2 bg-panel2/60 text-muted hover:border-muted/50 hover:text-ink",
);
export const btnAccent = cx(
  btnBase,
  "border-accent/50 bg-accent/10 text-accent hover:bg-accent/20",
);
export const btnOk = cx(
  btnBase,
  "border-ok/40 bg-ok/10 text-ok hover:bg-ok/20",
);

export const inputCls =
  "w-full rounded-md border border-edge bg-bg px-2.5 py-2 font-mono text-xs text-ink placeholder:text-muted/50 focus:border-info/60 focus:outline-none focus:ring-1 focus:ring-info/30";

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="group flex items-center gap-2.5 disabled:cursor-not-allowed disabled:opacity-50"
    >
      <span
        className={cx(
          "relative h-[18px] w-[32px] rounded-full border transition-colors",
          checked
            ? "border-ok/50 bg-ok/20"
            : "border-edge2 bg-edge group-hover:border-muted/40",
        )}
      >
        <span
          className={cx(
            "absolute top-[2px] h-3 w-3 rounded-full transition-all",
            checked ? "left-[16px] bg-ok" : "left-[2px] bg-muted",
          )}
        />
      </span>
      <span className="text-[10.5px] font-medium uppercase tracking-[0.16em] text-muted group-hover:text-ink">
        {label}
      </span>
    </button>
  );
}

/* ── icons (hand-rolled, lucide-style strokes) ───────────────────────────── */
function IconBase({
  d,
  className,
  viewBox = "0 0 24 24",
  strokeWidth = 2,
}: {
  d: string;
  className?: string;
  viewBox?: string;
  strokeWidth?: number;
}) {
  return (
    <svg
      viewBox={viewBox}
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      className={cx("h-3.5 w-3.5 shrink-0", className)}
    >
      <path d={d} />
    </svg>
  );
}

export const IconChevron = ({ className }: { className?: string }) => (
  <IconBase d="M6 9l6 6 6-6" className={className} />
);
export const IconCheck = ({ className }: { className?: string }) => (
  <IconBase d="M4 12.5l5 5L20 6.5" className={className} />
);
export const IconX = ({ className }: { className?: string }) => (
  <IconBase d="M6 6l12 12M18 6L6 18" className={className} />
);
export const IconZap = ({ className }: { className?: string }) => (
  <IconBase d="M13 2L4.1 13.5H11l-1.2 8.5L18.9 10.5H12L13 2z" className={className} />
);
export const IconRefresh = ({ className }: { className?: string }) => (
  <IconBase
    d="M21 12a9 9 0 1 1-2.6-6.4M21 3v6h-6"
    className={className}
  />
);
export const IconStop = ({ className }: { className?: string }) => (
  <IconBase d="M7 7h10v10H7z" className={className} />
);
export const IconArrowUpRight = ({ className }: { className?: string }) => (
  <IconBase d="M7 17L17 7M8 7h9v9" className={className} />
);

/* ── toast ───────────────────────────────────────────────────────────────── */
export function Toast({
  message,
  tone = "info",
  onDone,
}: {
  message: string;
  tone?: Tone;
  onDone: () => void;
}) {
  useEffect(() => {
    const t = setTimeout(onDone, 4500);
    return () => clearTimeout(t);
  }, [onDone, message]);
  return (
    <div
      role="status"
      className={cx(
        "fixed bottom-4 right-4 z-50 flex max-w-sm items-start gap-2 rounded-md border border-l-2 bg-panel px-3 py-2 shadow-2xl shadow-black/50",
        toneBorderL[tone],
        toneBorderSoft[tone],
      )}
    >
      <Dot tone={tone} pulse className="mt-1" />
      <span className="text-[12px] leading-snug text-ink">{message}</span>
    </div>
  );
}

/** Target-mark logo mark. */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      aria-hidden
      className={cx("h-5 w-5 shrink-0", className)}
    >
      <circle cx="16" cy="16" r="10" fill="none" stroke="#FF3B5C" strokeWidth="2.5" />
      <circle cx="16" cy="16" r="3.2" fill="#FF3B5C" />
      <path
        d="M16 1.5v5M16 25.5v5M1.5 16h5M25.5 16h5"
        stroke="#FF3B5C"
        strokeWidth="2.25"
        strokeLinecap="round"
      />
    </svg>
  );
}
