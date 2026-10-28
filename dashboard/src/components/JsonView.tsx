"use client";

import { useMemo, useState } from "react";
import { cx, IconChevron } from "./Bits";
import { oneLine } from "@/lib/format";

/** Collapsible JSON viewer for tool args and payloads. */
export function JsonView({
  value,
  label = "ARGS",
  defaultOpen = false,
  className,
}: {
  value: unknown;
  label?: string;
  defaultOpen?: boolean;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const pretty = useMemo(() => {
    try {
      return JSON.stringify(value ?? null, null, 2);
    } catch {
      return String(value);
    }
  }, [value]);

  if (value == null) return null;

  return (
    <div className={cx("min-w-0", className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex max-w-full items-center gap-1.5 rounded text-left font-mono text-[10px] tracking-wider text-muted/80 transition-colors hover:text-ink focus-visible:outline focus-visible:outline-1 focus-visible:outline-info/70"
      >
        <IconChevron
          className={cx("h-3 w-3 transition-transform", open && "rotate-180")}
        />
        <span className="uppercase">{label}</span>
        {!open && (
          <span className="min-w-0 truncate text-muted/50">
            {oneLine(value, 110)}
          </span>
        )}
      </button>
      {open && (
        <pre className="scroll-slim mt-1.5 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-edge bg-bg px-2 py-1.5 font-mono text-[10.5px] leading-relaxed text-ink/80">
          {pretty}
        </pre>
      )}
    </div>
  );
}
