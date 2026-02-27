"use client";

import { scoreToHue } from "vulnsig";

export function ScoreBadge({
  score,
  size = "md",
}: {
  score: number;
  size?: "sm" | "md" | "lg";
}) {
  const { hue, sat, light } = scoreToHue(score);
  // Match the glyph render: base lightness 52 * light multiplier
  const lightness = 52 * light;
  const bg = `hsl(${hue}, ${sat}%, ${lightness}%)`;
  const textColor = lightness > 40 ? "#000" : "#fff";

  const sizeClasses = {
    sm: "text-xs px-1.5 py-0.5",
    md: "text-sm px-2 py-0.5",
    lg: "text-base px-2.5 py-1",
  };

  return (
    <span
      className={`inline-flex items-center font-mono font-semibold rounded ${sizeClasses[size]}`}
      style={{ backgroundColor: bg, color: textColor }}
    >
      {score.toFixed(1)}
    </span>
  );
}
