"use client";

import type React from "react";
import {
  Bar,
  BarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { MetricTag } from "./MetricTag";
import { metricColor, shiftedColor } from "@/lib/distributionColors";
import {
  isEmptyValue,
  MergedMetric,
  valueOpacity,
} from "@/lib/metricMerge";

interface Props {
  metrics: MergedMetric[];
  total: number;
}

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
  color: string;
}

// Renders each stacked segment with a 1px right-edge inset to create a gap
// between adjacent segments. For very thin slices (e.g. 1 result out of 400+),
// the inset would consume the whole segment, so we fall back to drawing the
// full width with a 1px minimum so a single-result value still shows as a
// hairline rather than disappearing.
interface SegmentShapeProps {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  fill?: string;
  fillOpacity?: number;
  payload?: Record<string, number | string>;
  dataKey?: string;
}
function SegmentShape(rawProps: unknown): React.ReactElement {
  const props = rawProps as SegmentShapeProps;
  const {
    x = 0,
    y = 0,
    width = 0,
    height = 0,
    fill,
    fillOpacity,
    payload,
    dataKey,
  } = props;
  const count =
    typeof dataKey === "string" ? Number(payload?.[dataKey] ?? 0) : 0;
  if (!fill || fill === "transparent" || count === 0 || width <= 0) {
    return <g />;
  }
  const GAP = 2;
  const MIN = 2;
  const drawn = width > GAP + MIN ? width - GAP : Math.max(MIN, width);
  return (
    <rect
      x={x}
      y={y}
      width={drawn}
      height={height}
      fill={fill}
      fillOpacity={fillOpacity}
    />
  );
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
                  fill={
                    empty ? "transparent" : shiftedColor(metric.key, v.value)
                  }
                  fillOpacity={empty ? 0 : valueOpacity(metric.key, v.value)}
                  shape={SegmentShape}
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
