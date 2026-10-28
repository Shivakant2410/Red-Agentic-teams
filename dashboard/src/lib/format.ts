/** Formatting helpers: ages, durations, clocks, token counts. */

export function parseTs(ts?: string | null): number | null {
  if (!ts) return null;
  const t = Date.parse(ts);
  return Number.isFinite(t) ? t : null;
}

const pad2 = (n: number): string => String(n).padStart(2, "0");

/** HH:MM:SS in the viewer's local timezone. */
export function formatClock(ts?: string | null): string {
  const t = parseTs(ts);
  if (t == null) return "--:--:--";
  const d = new Date(t);
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

/** 38s · 4m 12s · 1h 06m · 3d 04h */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d > 0) return `${d}d ${pad2(h)}h`;
  if (h > 0) return `${h}h ${pad2(m)}m`;
  if (m > 0) return `${m}m ${pad2(sec)}s`;
  return `${sec}s`;
}

/** Relative age ("4m ago") or clock fallback for old events. */
export function formatAge(ts: string | null | undefined, now: number): string {
  const t = parseTs(ts);
  if (t == null) return "—";
  const delta = now - t;
  if (delta < 0) return formatClock(ts);
  if (delta < 60_000) return "just now";
  if (delta < 8 * 3600_000) return `${formatDuration(delta)} ago`;
  return formatClock(ts);
}

/** 842 · 12.4k · 3.1M */
export function formatTokens(n?: number | null): string {
  if (n == null || !Number.isFinite(n)) return "—";
  if (n < 1000) return String(n);
  if (n < 1_000_000) {
    const v = n / 1000;
    return `${v < 100 ? v.toFixed(1) : Math.round(v)}k`.replace(".0", "");
  }
  const v = n / 1_000_000;
  return `${v.toFixed(1)}M`.replace(".0", "");
}

export function fmtInt(n?: number | null): string {
  if (n == null || !Number.isFinite(n)) return "—";
  return n.toLocaleString("en-US");
}

export function truncate(s: string, max: number): string {
  if (!s) return "";
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

/** Single-line compact rendering of arbitrary args/JSON for inline previews. */
export function oneLine(value: unknown, max = 140): string {
  let text: string;
  if (typeof value === "string") text = value;
  else {
    try {
      text = JSON.stringify(value ?? null);
    } catch {
      text = String(value);
    }
  }
  text = text.replace(/\s+/g, " ").trim();
  return truncate(text, max);
}
