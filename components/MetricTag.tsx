"use client";

import { metricColor } from "@/lib/distributionColors";

export { metricColor };

export function MetricTag({ label, color }: { label: string; color?: string }) {
  const c = color || "#6366f1";
  return (
    <span
      className="inline-block px-1 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider align-middle"
      style={{
        background: `${c}22`,
        color: c,
        border: `1px solid ${c}44`,
      }}
    >
      {label}
    </span>
  );
}

export function ValueTag({ label }: { label: string }) {
  return (
    <span className="inline-block px-1 py-0.5 rounded text-[10px] font-mono font-semibold align-middle bg-white/[0.06] text-slate-400 border border-white/[0.08]">
      {label}
    </span>
  );
}
