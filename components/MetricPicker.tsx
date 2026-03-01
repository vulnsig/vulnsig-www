"use client";

import { MetricTag, metricColor } from "./MetricTag";

interface MetricDef {
  key: string;
  name: string;
  values: string[];
  labels: string[];
}

const METRIC_GROUPS_40: { title: string; metrics: MetricDef[] }[] = [
  {
    title: "Exploitability",
    metrics: [
      { key: "AV", name: "Attack Vector", values: ["N", "A", "L", "P"], labels: ["Network", "Adjacent", "Local", "Physical"] },
      { key: "AC", name: "Attack Complexity", values: ["L", "H"], labels: ["Low", "High"] },
      { key: "AT", name: "Attack Requirements", values: ["N", "P"], labels: ["None", "Present"] },
      { key: "PR", name: "Privileges Required", values: ["N", "L", "H"], labels: ["None", "Low", "High"] },
      { key: "UI", name: "User Interaction", values: ["N", "P", "A"], labels: ["None", "Passive", "Active"] },
    ],
  },
  {
    title: "Vulnerable System Impact",
    metrics: [
      { key: "VC", name: "Confidentiality", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "VI", name: "Integrity", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "VA", name: "Availability", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
    ],
  },
  {
    title: "Subsequent System Impact",
    metrics: [
      { key: "SC", name: "Confidentiality", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "SI", name: "Integrity", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "SA", name: "Availability", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
    ],
  },
];

const METRIC_GROUPS_31: { title: string; metrics: MetricDef[] }[] = [
  {
    title: "Exploitability",
    metrics: [
      { key: "AV", name: "Attack Vector", values: ["N", "A", "L", "P"], labels: ["Network", "Adjacent", "Local", "Physical"] },
      { key: "AC", name: "Attack Complexity", values: ["L", "H"], labels: ["Low", "High"] },
      { key: "PR", name: "Privileges Required", values: ["N", "L", "H"], labels: ["None", "Low", "High"] },
      { key: "UI", name: "User Interaction", values: ["N", "R"], labels: ["None", "Required"] },
    ],
  },
  {
    title: "Scope",
    metrics: [
      { key: "S", name: "Scope", values: ["U", "C"], labels: ["Unchanged", "Changed"] },
    ],
  },
  {
    title: "Impact",
    metrics: [
      { key: "C", name: "Confidentiality", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "I", name: "Integrity", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
      { key: "A", name: "Availability", values: ["H", "L", "N"], labels: ["High", "Low", "None"] },
    ],
  },
];

function parseVectorMetrics(vector: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  const parts = vector.split("/");
  for (const part of parts) {
    const [key, val] = part.split(":");
    if (key && val && key !== "CVSS") {
      metrics[key] = val;
    }
  }
  return metrics;
}

export function MetricPicker({
  vector,
  onChange,
}: {
  vector: string;
  onChange: (vector: string) => void;
}) {
  const is31 = vector.startsWith("CVSS:3.1/") || vector.startsWith("CVSS:3.0/");
  const groups = is31 ? METRIC_GROUPS_31 : METRIC_GROUPS_40;
  const metrics = parseVectorMetrics(vector);

  function handleChange(key: string, value: string) {
    // Replace the single metric in-place to avoid parse/rebuild mixing vectors
    const newVector = vector.replace(
      new RegExp(`(?<=/)${key}:[^/]+`),
      `${key}:${value}`
    );
    onChange(newVector);
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-6 p-6">
      {groups.map((group) => (
        <div key={group.title}>
          <h3 className="text-xs font-mono text-zinc-500 uppercase tracking-wider mb-3">
            {group.title}
          </h3>
          <div className="space-y-3">
            {group.metrics.map((metric) => (
              <div key={metric.key}>
                <label className="text-xs text-zinc-400 mb-1 flex items-center gap-1.5">
                  <MetricTag label={metric.key} color={metricColor(metric.key)} />
                  <span>{metric.name}</span>
                </label>
                <div className="flex rounded overflow-hidden border border-zinc-700">
                  {metric.values.map((val, i) => {
                    const isActive = metrics[metric.key] === val;
                    return (
                      <button
                        key={val}
                        onClick={() => handleChange(metric.key, val)}
                        className={`metric-btn flex-1 py-1 text-xs font-mono text-center border-r border-zinc-700 last:border-r-0 cursor-pointer ${
                          isActive
                            ? "bg-zinc-700 text-zinc-100"
                            : "bg-zinc-800/50 text-zinc-500 hover:bg-zinc-700/50 hover:text-zinc-300"
                        }`}
                        title={metric.labels[i]}
                      >
                        {val}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
