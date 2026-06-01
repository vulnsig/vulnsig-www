"use client";

import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { MetricTag, metricColor } from "./MetricTag";
import { MergedMetric, valueColor } from "@/lib/metricMerge";

interface Props {
  metrics: MergedMetric[];
}

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
  color: string;
}

const BAR_OPACITY = 0.7;

// Impact metrics use H/L/N where "N" means *no impact*, so that segment is the
// genuinely empty case and should render as a blank slot. Exploitability
// metrics like AV/PR/UI/AT also use "None", but there "None" is a meaningful
// exploit characteristic (no privileges required, no user interaction needed)
// and should stay colored. "Not Defined" (E:X, E:ND) is treated as empty
// across the board.
const IMPACT_METRICS = new Set([
  "C", "I", "A",
  "VC", "VI", "VA",
  "SC", "SI", "SA",
]);

function isEmptyValue(metricKey: string, value: string, label: string): boolean {
  if (label === "Not Defined") return true;
  return IMPACT_METRICS.has(metricKey) && value === "N";
}

function StackedTooltip({
  active,
  payload,
  metric,
}: {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  metric: MergedMetric;
}) {
  if (!active || !payload || payload.length === 0) return null;
  const labelFor = (v: string) =>
    metric.values.find((x) => x.value === v)?.label ?? v;
  return (
    <div
      style={{
        backgroundColor: "#27272a",
        border: "1px solid #52525b",
        padding: "6px 10px",
        borderRadius: 4,
        fontSize: 11,
        color: "#e4e4e7",
        fontFamily: "var(--font-mono, ui-monospace)",
        minWidth: 140,
      }}
    >
      <div style={{ color: metricColor(metric.key), fontWeight: 600, marginBottom: 4 }}>
        {metric.key} · {metric.title}
      </div>
      {payload.map((p) => (
        <div
          key={p.dataKey}
          style={{ display: "flex", justifyContent: "space-between", gap: 12 }}
        >
          <span style={{ color: p.color }}>
            {p.dataKey} {labelFor(p.dataKey)}
          </span>
          <span style={{ color: "#a1a1aa" }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

function MetricRow({ metric }: { metric: MergedMetric }) {
  const datum: Record<string, number | string> = { name: metric.key };
  for (const v of metric.values) datum[v.value] = v.count;

  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <MetricTag label={metric.key} color={metricColor(metric.key)} />
        <span className="text-xs text-zinc-400 truncate">{metric.title}</span>
      </div>
      <div style={{ height: 22 }} className="w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={[datum]}
            layout="vertical"
            margin={{ top: 0, right: 0, left: 0, bottom: 0 }}
            barCategoryGap={0}
          >
            <XAxis type="number" hide domain={[0, metric.totalCount]} />
            <YAxis type="category" dataKey="name" hide />
            <Tooltip
              content={<StackedTooltip metric={metric} />}
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
              wrapperStyle={{ outline: "none" }}
            />
            {metric.values.map((v) => {
              const empty = isEmptyValue(metric.key, v.value, v.label);
              return (
                <Bar
                  key={v.value}
                  dataKey={v.value}
                  stackId="a"
                  fill={empty ? "transparent" : valueColor(metric.key, v.value)}
                  fillOpacity={empty ? 0 : BAR_OPACITY}
                  isAnimationActive={false}
                />
              );
            })}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0 text-[10px] font-mono text-zinc-500">
        {metric.values.map((v) => {
          const empty = isEmptyValue(metric.key, v.value, v.label);
          return (
            <span key={v.value}>
              <span
                style={{
                  color: empty ? "#71717a" : valueColor(metric.key, v.value),
                }}
              >
                {v.value}
              </span>
              <span className="text-zinc-600">:</span>
              {v.count}
            </span>
          );
        })}
      </div>
    </div>
  );
}

export function VectorDistribution({ metrics }: Props) {
  if (metrics.length === 0) return null;
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-4">
      {metrics.map((m) => (
        <MetricRow key={m.key} metric={m} />
      ))}
    </div>
  );
}
