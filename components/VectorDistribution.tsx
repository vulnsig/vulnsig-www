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
import { MergedMetric, valueHueOffset, valueOpacity } from "@/lib/metricMerge";

// Parse "#rrggbb" into HSL components. Used to derive a hue baseline from
// each metric's tag color so per-value hue offsets (valueHueOffset) can be
// applied around it.
function hexToHsl(hex: string): { h: number; s: number; l: number } {
  const r = parseInt(hex.slice(1, 3), 16) / 255;
  const g = parseInt(hex.slice(3, 5), 16) / 255;
  const b = parseInt(hex.slice(5, 7), 16) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  if (max === min) return { h: 0, s: 0, l: l * 100 };
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h: number;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) * 60;
  else if (max === g) h = ((b - r) / d + 2) * 60;
  else h = ((r - g) / d + 4) * 60;
  return { h, s: s * 100, l: l * 100 };
}

function shiftedColor(metricKey: string, value: string): string {
  const { h, s, l } = hexToHsl(metricColor(metricKey));
  const offset = valueHueOffset(metricKey, value);
  const newH = (((h + offset) % 360) + 360) % 360;
  return `hsl(${newH.toFixed(1)}, ${s.toFixed(1)}%, ${l.toFixed(1)}%)`;
}

interface Props {
  metrics: MergedMetric[];
  total: number;
}

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
  color: string;
}

// Impact metrics use H/L/N where "N" means *no impact*, so that segment is the
// genuinely empty case and should render as a blank slot. Exploitability
// metrics like AV/PR/UI/AT also use "None", but there "None" is a meaningful
// exploit characteristic (no privileges required, no user interaction needed)
// and should stay colored. "Not Defined" (E:X, E:ND) is treated as empty
// across the board.
const IMPACT_METRICS = new Set([
  "C",
  "I",
  "A",
  "VC",
  "VI",
  "VA",
  "SC",
  "SI",
  "SA",
]);

function isEmptyValue(
  metricKey: string,
  value: string,
  label: string,
): boolean {
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
  const color = metricColor(metric.key);
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
      <div style={{ marginBottom: 4 }}>
        <span style={{ color, fontWeight: 600 }}>{metric.key}</span>
        <span> {metric.title}</span>
      </div>
      {payload.map((p) => (
        <div
          key={p.dataKey}
          style={{ display: "flex", justifyContent: "space-between", gap: 12 }}
        >
          <span>
            <span style={{ color, fontWeight: 600 }}>{p.dataKey}</span>
            <span> {labelFor(p.dataKey)}</span>
          </span>
          <span>{p.value}</span>
        </div>
      ))}
    </div>
  );
}

function MetricRow({ metric, total }: { metric: MergedMetric; total: number }) {
  const datum: Record<string, number | string> = { name: metric.key };
  for (const v of metric.values) datum[v.value] = v.count;
  // Domain is the full result-set size so version-specific metrics like
  // SC/SI/SA (4.0 only) render their bar relative to all CVEs in the search,
  // not just the 4.0 subset. Results missing the metric leave the rest of the
  // bar visually empty.
  const domainMax = Math.max(total, metric.totalCount);

  return (
    <div className="flex flex-col gap-1 relative hover:z-50">
      <div className="flex items-center gap-2">
        <MetricTag label={metric.key} color={metricColor(metric.key)} />
        <span className="text-xs text-zinc-400 truncate">{metric.title}</span>
      </div>
      <div style={{ height: 12 }} className="w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={[datum]}
            layout="vertical"
            margin={{ top: 0, right: 0, left: 0, bottom: 0 }}
            barCategoryGap={0}
          >
            <XAxis type="number" hide domain={[0, domainMax]} />
            <YAxis type="category" dataKey="name" hide />
            <Tooltip
              content={<StackedTooltip metric={metric} />}
              cursor={{ fill: "rgba(255,255,255,0.04)" }}
              wrapperStyle={{ outline: "none", zIndex: 50 }}
              allowEscapeViewBox={{ x: true, y: true }}
            />
            {metric.values.map((v) => {
              const empty = isEmptyValue(metric.key, v.value, v.label);
              return (
                <Bar
                  key={v.value}
                  dataKey={v.value}
                  stackId="a"
                  fill={empty ? "transparent" : shiftedColor(metric.key, v.value)}
                  fillOpacity={empty ? 0 : valueOpacity(metric.key, v.value)}
                  isAnimationActive={false}
                />
              );
            })}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap gap-x-2 gap-y-0 text-[10px] font-mono text-zinc-500">
        {metric.values.map((v) => {
          const empty = isEmptyValue(metric.key, v.value, v.label);
          return (
            <span key={v.value}>
              <span
                style={{
                  color: empty ? "#71717a" : shiftedColor(metric.key, v.value),
                  opacity: empty ? 1 : valueOpacity(metric.key, v.value),
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

export function VectorDistribution({ metrics, total }: Props) {
  if (metrics.length === 0) return null;
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-4 gap-y-2">
      {metrics.map((m) => (
        <MetricRow key={m.key} metric={m} total={total} />
      ))}
    </div>
  );
}
