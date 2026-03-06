"use client";

const METRIC_COLORS: Record<string, string> = {
  AV: "#8b5cf6",
  AC: "#ec4899",
  AT: "#ef4444",
  PR: "#f97316",
  UI: "#f97316",
  VC: "#6366f1",
  VI: "#6366f1",
  VA: "#6366f1",
  SC: "#f59e0b",
  SI: "#f59e0b",
  SA: "#f59e0b",
  S: "#ef4444",
  C: "#6366f1",
  I: "#6366f1",
  A: "#6366f1",
  "V*": "#6366f1",
  "S*": "#f59e0b",
  E: "#14b8a6",
  Score: "#10b981",
};

export function metricColor(key: string): string {
  return METRIC_COLORS[key] || "#6366f1";
}

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
