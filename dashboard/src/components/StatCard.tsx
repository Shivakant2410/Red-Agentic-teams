"use client";

import type { ReactNode } from "react";
import { cx, Micro, Panel } from "./Bits";

/** Compact stat tile used in the overview + mission-control stat rows. */
export function StatCard({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Panel className={cx("px-3 py-2.5", className)}>
      <Micro className="mb-1.5">{label}</Micro>
      <div className="flex items-baseline gap-2 text-[17px] font-semibold leading-none text-ink tabular-nums">
        {children}
      </div>
    </Panel>
  );
}
