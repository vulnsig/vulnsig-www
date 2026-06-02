import { scoreToHue } from "vulnsig";
import { valueHueOffset } from "./metricMerge";

const METRIC_COLORS: Record<string, string> = {
  AV: "#8b5cf6",
  AC: "#ec4899",
  AT: "#ef4444",
  PR: "#f97316",
  Au: "#f97316",
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

export function hexToHsl(hex: string): { h: number; s: number; l: number } {
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

export function shiftedColor(metricKey: string, value: string): string {
  const { h, s, l } = hexToHsl(metricColor(metricKey));
  const offset = valueHueOffset(metricKey, value);
  const newH = (((h + offset) % 360) + 360) % 360;
  return `hsl(${newH.toFixed(1)}, ${s.toFixed(1)}%, ${l.toFixed(1)}%)`;
}

export function binColor(score: number): string {
  const { hue, sat, light } = scoreToHue(score);
  return `hsl(${hue.toFixed(1)}, ${sat.toFixed(1)}%, ${(52 * light).toFixed(1)}%)`;
}
