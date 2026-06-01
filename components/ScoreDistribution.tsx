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
import { scoreToHue } from "vulnsig";

interface Props {
  distribution: Record<string, number>;
}

interface Bin {
  bin: number;
  count: number;
  color: string;
}

function binColor(score: number): string {
  const { hue, sat, light } = scoreToHue(score);
  return `hsl(${hue.toFixed(1)}, ${sat.toFixed(1)}%, ${(52 * light).toFixed(1)}%)`;
}

function ScoreTooltip({ active, payload }: { active?: boolean; payload?: unknown[] }) {
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
      <div style={{ color: datum.color, fontWeight: 600 }}>
        score {datum.bin}–{datum.bin + 1}
      </div>
      <div style={{ color: "#a1a1aa" }}>
        {datum.count} {datum.count === 1 ? "result" : "results"}
      </div>
    </div>
  );
}

export function ScoreDistribution({ distribution }: Props) {
  const data: Bin[] = [];
  for (let i = 0; i <= 10; i++) {
    const key = String(i);
    const count = distribution[key] ?? 0;
    data.push({ bin: i, count, color: binColor(i) });
  }
  const maxCount = Math.max(...data.map((d) => d.count));
  if (maxCount === 0) return null;

  return (
    <div className="w-full" style={{ height: 140 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 8, right: 8, left: 0, bottom: 4 }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#3f3f46"
            vertical={false}
          />
          <XAxis
            dataKey="bin"
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
              <Cell key={d.bin} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
