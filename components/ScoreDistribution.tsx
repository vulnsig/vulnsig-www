"use client";

import {
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { binColor } from "@/lib/distributionColors";

interface Props {
  distribution: Record<string, number>;
}

interface Bin {
  label: string;
  count: number;
  color: string;
}

// The 0–1 and 9–10 ends of the CVSS scale get collapsed into single bins.
// 0.x scores are essentially "no severity" and 9–10 are both Critical — both
// rare tails read better as combined buckets than as two skinny columns.
const BIN_DEFS: { label: string; floors: number[]; colorScore: number }[] = [
  { label: "0–1", floors: [0, 1], colorScore: 1 },
  { label: "2", floors: [2], colorScore: 2.5 },
  { label: "3", floors: [3], colorScore: 3.5 },
  { label: "4", floors: [4], colorScore: 4.5 },
  { label: "5", floors: [5], colorScore: 5.5 },
  { label: "6", floors: [6], colorScore: 6.5 },
  { label: "7", floors: [7], colorScore: 7.5 },
  { label: "8", floors: [8], colorScore: 8.5 },
  { label: "9–10", floors: [9, 10], colorScore: 10 },
];

function ScoreTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: unknown[];
}) {
  if (!active || !payload || payload.length === 0) return null;
  const datum = (payload[0] as { payload: Bin }).payload;
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
      }}
    >
      <div>
        <span style={{ color: datum.color, fontWeight: 600 }}>
          score {datum.label}
        </span>
      </div>
      <div>
        {datum.count} {datum.count === 1 ? "result" : "results"}
      </div>
    </div>
  );
}

export function ScoreDistribution({ distribution }: Props) {
  const data: Bin[] = BIN_DEFS.map((def) => ({
    label: def.label,
    count: def.floors.reduce((s, f) => s + (distribution[String(f)] ?? 0), 0),
    color: binColor(def.colorScore),
  }));
  const maxCount = Math.max(...data.map((d) => d.count));
  if (maxCount === 0) return null;

  return (
    <div className="w-full" style={{ height: 140 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 8, right: 8, left: 0, bottom: 4 }}
          barCategoryGap="5%"
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#3f3f46"
            vertical={false}
          />
          <XAxis
            dataKey="label"
            tick={{ fill: "#a1a1aa", fontSize: 10 }}
            axisLine={{ stroke: "#52525b" }}
            tickLine={{ stroke: "#52525b" }}
          />
          <YAxis
            tick={{ fill: "#a1a1aa", fontSize: 10 }}
            axisLine={{ stroke: "#52525b" }}
            tickLine={{ stroke: "#52525b" }}
            allowDecimals={false}
            width={30}
          />
          <Tooltip
            content={<ScoreTooltip />}
            cursor={{ fill: "rgba(255,255,255,0.04)" }}
            wrapperStyle={{ outline: "none" }}
          />
          <Bar dataKey="count" stroke="#3f3f46" strokeWidth={0.5}>
            {data.map((d) => (
              <Cell key={d.label} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
