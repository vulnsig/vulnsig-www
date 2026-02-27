"use client";

import { VulnSig } from "vulnsig-react";
import type { Vulnerability, Callout } from "@/data/vulnerabilities";

const LETTERS = ["A", "B", "C", "D", "E", "F"];

// Position a letter marker near the relevant feature on the glyph
function getMarkerPosition(anchor: Callout["anchor"], glyphSize: number) {
  const r = glyphSize / 2;
  const offset = r * 0.72; // distance from center for markers

  const positions: Record<Callout["anchor"], { x: number; y: number }> = {
    center:         { x: 0,             y: 0 },
    top:            { x: 0,             y: -offset },
    "top-right":    { x: offset * 0.7,  y: -offset * 0.7 },
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
  const glyphSize = 220;
  const svgSize = glyphSize + 40; // padding for markers
  const cx = svgSize / 2;
  const cy = svgSize / 2;
  const callouts = vuln.callouts ?? [];

  return (
    <div className="flex items-center gap-8 max-w-2xl w-full px-4">
      {/* Left: glyph with letter markers */}
      <div className="flex-none relative" style={{ width: svgSize, height: svgSize }}>
        <div
          className="absolute"
          style={{ left: (svgSize - glyphSize) / 2, top: (svgSize - glyphSize) / 2 }}
        >
          <VulnSig vector={vuln.vector} size={glyphSize} score={vuln.score} />
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
        <div className="mb-3">
          <p className="font-semibold text-sm text-zinc-200">{vuln.name}</p>
          {vuln.cve && (
            <p className="font-mono text-xs text-zinc-600">{vuln.cve}</p>
          )}
        </div>
        <ul className="space-y-2">
          {callouts.map((callout, i) => {
            const delay = `${i * 0.2}s`;
            return (
              <li
                key={callout.feature}
                className="flex gap-2.5 items-start callout-animate"
                style={{ animationDelay: delay }}
              >
                <span className="flex-none w-5 h-5 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center text-[10px] font-mono font-semibold text-zinc-400 mt-0.5">
                  {LETTERS[i]}
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
