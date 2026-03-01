"use client";

import { useMemo } from "react";
import { VulnSig } from "vulnsig-react";
import { calculateScore } from "vulnsig";
import type { Vulnerability } from "@/data/vulnerabilities";

interface Callout {
  feature: string;
  label: string;
  anchor: "center" | "top" | "top-right" | "right" | "bottom-right" | "bottom" | "bottom-left" | "left" | "top-left" | "inner-left" | "inner-right";
}
import { MetricTag, metricColor } from "./MetricTag";

const LETTERS = ["A", "B", "C", "D", "E", "F"];

interface AutoCallout extends Callout {
  metrics?: string[];
}

/* ── Auto-generate callouts from parsed vector metrics ── */

function parseMetrics(vector: string): Record<string, string> {
  const m: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [key, val] = part.split(":");
    if (key && val && key !== "CVSS") m[key] = val;
  }
  return m;
}

const AV_LABELS: Record<string, string> = {
  N: "8 points: Network attack",
  A: "6 points: Adjacent network",
  L: "4 points: Local access",
  P: "3 points: Physical access",
};

const AC_LABELS: Record<string, string> = {
  L: "Sharp: Low complexity",
  H: "Blunt: High complexity",
};

const PR_LABELS: Record<string, string> = {
  N: "Thin outline: No privileges needed",
  L: "Medium stroke: Low privileges",
  H: "Thick outline: High privileges",
};

const UI_LABELS: Record<string, string> = {
  N: "Spikes: No user interaction",
  R: "Smooth edge: Interaction required",
  P: "Bumps: Passive interaction",
  A: "Smooth edge: Active interaction",
};

const CIA_NAMES: Record<string, string> = { C: "Confidentiality", I: "Integrity", A: "Availability" };
const LEVEL_NAMES: Record<string, string> = { H: "high", L: "low" };

function formatImpact(pairs: [string, string][], metricPrefix = ""): { label: string; metrics: string[] } {
  const active = pairs.filter(([, v]) => v !== "N");
  const metrics = active.map(([k]) => metricPrefix + k);
  const allSame = active.every(([, v]) => v === active[0][1]);
  if (active.length === pairs.length && allSame) {
    return { label: `All sectors ${LEVEL_NAMES[active[0][1]]}: Full CIA impact`, metrics };
  }
  if (active.length === pairs.length) {
    const desc = active.map(([k, v]) => `${CIA_NAMES[k]} ${LEVEL_NAMES[v]}`).join(", ");
    return { label: desc, metrics };
  }
  if (active.length === 0) return { label: "All sectors dark: No CIA impact", metrics: [] };
  const desc = active.map(([k, v]) => `${CIA_NAMES[k]} ${LEVEL_NAMES[v]}`).join(", ");
  return { label: desc, metrics };
}

function ciaCallout(m: Record<string, string>): { label: string; metrics: string[] } | null {
  // CVSS 4.0: VC/VI/VA + SC/SI/SA
  if (m.VC != null) {
    const vuln = formatImpact([["C", m.VC], ["I", m.VI], ["A", m.VA]], "V");
    const sub = formatImpact([["C", m.SC], ["I", m.SI], ["A", m.SA]], "S");
    const parts: string[] = [];
    if (vuln.metrics.length > 0) parts.push(`Vulnerable: ${vuln.label}`);
    if (sub.metrics.length > 0) parts.push(`Subsequent: ${sub.label}`);
    if (parts.length === 0) return { label: "All sectors dark: No CIA impact", metrics: [] };
    return {
      label: parts.join(" · "),
      metrics: [...vuln.metrics, ...sub.metrics],
    };
  }
  // CVSS 3.x: C/I/A
  if (m.C != null) {
    return formatImpact([["C", m.C], ["I", m.I], ["A", m.A]]);
  }
  return null;
}

function autoCallouts(vector: string): Callout[] {
  const m = parseMetrics(vector);
  const out: AutoCallout[] = [];

  if (m.AV && AV_LABELS[m.AV]) {
    out.push({ feature: "star-points", label: AV_LABELS[m.AV], anchor: "center" });
  }
  if (m.AC && AC_LABELS[m.AC]) {
    out.push({ feature: "star-shape", label: AC_LABELS[m.AC], anchor: m.AC === "L" ? "inner-right" : "inner-left" });
  }
  if (m.PR && PR_LABELS[m.PR]) {
    out.push({ feature: "star-outline", label: PR_LABELS[m.PR], anchor: "left" });
  }
  if (m.UI && UI_LABELS[m.UI]) {
    const feature = m.UI === "N" ? "spikes" : "smooth-edge";
    out.push({ feature, label: UI_LABELS[m.UI], anchor: "top-right" });
  }
  const cia = ciaCallout(m);
  if (cia) {
    out.push({ feature: "ring-brightness", label: cia.label, anchor: "right", metrics: cia.metrics });
  }

  return out;
}

const FEATURE_METRICS: Record<string, string[]> = {
  "star-points": ["AV"],
  "star-shape": ["AC"],
  "star-outline": ["PR"],
  "spikes": ["UI"],
  "smooth-edge": ["UI"],
  "ring-brightness": ["C", "I", "A"],
  "split-band": ["S"],
  "segmentation": ["AT"],
  "color": ["Score"],
};

// Position a letter marker near the relevant feature on the glyph
function getMarkerPosition(anchor: Callout["anchor"], glyphSize: number) {
  const r = glyphSize / 2;
  const offset = r * 0.72; // distance from center for markers

  const positions: Record<Callout["anchor"], { x: number; y: number }> = {
    center:         { x: 0,             y: 0 },
    top:            { x: 0,             y: -offset },
    "top-right":    { x: offset * 1.0,  y: -offset * 1.0 },
    right:          { x: offset,        y: 0 },
    "bottom-right": { x: offset * 0.7,  y: offset * 0.7 },
    bottom:         { x: 0,             y: offset },
    "bottom-left":  { x: -offset * 0.7, y: offset * 0.7 },
    left:           { x: -offset,       y: 0 },
    "top-left":     { x: -offset * 0.7, y: -offset * 0.7 },
    "inner-left":   { x: -offset * 0.4, y: offset * 0.15 },
    "inner-right":  { x: offset * 0.4,  y: offset * 0.15 },
  };

  return positions[anchor];
}

export function HeroGlyph({ vuln }: { vuln: Vulnerability }) {
  const glyphSize = 200;
  const svgSize = glyphSize + 40; // padding for markers
  const cx = svgSize / 2;
  const cy = svgSize / 2;
  const callouts: AutoCallout[] = useMemo(() => autoCallouts(vuln.vector), [vuln.vector]);

  return (
    <div className="flex items-center gap-0 max-w-2xl w-full px-4">
      {/* Left: glyph with letter markers */}
      <div className="flex-none relative" style={{ width: svgSize, height: svgSize }}>
        <div
          className="absolute"
          style={{ left: (svgSize - glyphSize) / 2, top: (svgSize - glyphSize) / 2 }}
        >
          <VulnSig vector={vuln.vector} size={glyphSize} score={calculateScore(vuln.vector)} />
        </div>

        {/* Letter markers overlaid on glyph */}
        <svg
          className="absolute inset-0 pointer-events-none"
          width={svgSize}
          height={svgSize}
          viewBox={`0 0 ${svgSize} ${svgSize}`}
        >
          {callouts.map((callout, i) => {
            const pos = getMarkerPosition(callout.anchor, glyphSize);
            const mx = cx + pos.x;
            const my = cy + pos.y;
            const delay = `${i * 0.2}s`;

            return (
              <g
                key={callout.feature}
                className="callout-animate"
                style={{ animationDelay: delay }}
              >
                <circle
                  cx={mx}
                  cy={my}
                  r={11}
                  fill="rgba(0,0,0,0.7)"
                  stroke="rgba(255,255,255,0.3)"
                  strokeWidth={1}
                />
                <text
                  x={mx}
                  y={my}
                  textAnchor="middle"
                  dominantBaseline="central"
                  style={{
                    fontSize: "11px",
                    fontFamily: "var(--font-mono), monospace",
                    fontWeight: 600,
                    fill: "rgba(255,255,255,0.85)",
                  }}
                >
                  {LETTERS[i]}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Right: callout legend */}
      <div className="flex-1 min-w-0">
        <div className="mb-4">
          <p className="font-semibold text-sm text-zinc-200">{vuln.name}</p>
          {vuln.cve && (
            <p className="font-mono text-xs text-zinc-500">{vuln.cve}</p>
          )}
        </div>
        <ul className="space-y-2">
          {callouts.map((callout, i) => {
            const delay = `${i * 0.2}s`;
            return (
              <li
                key={callout.feature}
                className="flex gap-2 items-start callout-animate"
                style={{ animationDelay: delay }}
              >
                <span className="flex-none w-5 h-5 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-[10px] font-mono font-semibold text-zinc-400">
                  {LETTERS[i]}
                </span>
                <span className="inline-flex flex-wrap gap-1">
                  {(callout.metrics ?? FEATURE_METRICS[callout.feature] ?? []).map((k) => (
                    <MetricTag key={k} label={k} color={metricColor(k)} />
                  ))}
                </span>
                <span className="text-sm text-zinc-400 leading-relaxed">
                  {callout.label}
                </span>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
