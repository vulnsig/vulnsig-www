import {
  isEmptyValue,
  mergeVectorDistribution,
  MergedMetric,
  valueOpacity,
} from "./metricMerge";
import { binColor, metricColor, shiftedColor } from "./distributionColors";

const FONT = "ui-monospace, SFMono-Regular, Menlo, monospace";

// Background-agnostic text palette. Tailwind gray-400 / gray-500 / gray-600
// sit around 45–65 % lightness so the same hex reads on both #fff and #18181b
// without retuning. Hierarchy comes from picking neighboring stops, not from
// reaching for very light/very dark anchors.
const TEXT_STRONG = "#4b5563"; // gray-600 — title, value counts
const TEXT_BODY = "#6b7280"; // gray-500 — section labels, axis labels, footer
const TEXT_MUTED = "#9ca3af"; // gray-400 — colons, "empty" value labels
const GRID_STROKE = "#9ca3af"; // gray-400 + stroke-opacity below for subtlety
const GRID_OPACITY = "0.3";
const BAR_STROKE = "#6b7280";
const BAR_STROKE_OPACITY = "0.4";

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

export interface RenderDistributionInput {
  query: string;
  total: number;
  truncated: boolean;
  scoreDistribution: Record<string, number>;
  vectorDistribution: Record<string, Record<string, number>>;
  width?: number;
  generatedAt?: Date;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function clamp(n: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, n));
}

function fmt(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(2);
}

function formatDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

// Pick a small set of nice round Y-axis ticks for a histogram whose max
// count is `maxValue`. Returns ticks like [0, 25, 50, 75, 100] for max=92.
function niceTicks(maxValue: number, target = 4): number[] {
  if (maxValue <= 0) return [0, 1];
  const rawStep = maxValue / target;
  const mag = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const norm = rawStep / mag;
  const step =
    norm < 1.5 ? 1 * mag : norm < 3 ? 2 * mag : norm < 7 ? 5 * mag : 10 * mag;
  const out: number[] = [];
  let v = 0;
  while (v < maxValue) {
    out.push(v);
    v += step;
  }
  out.push(v);
  return out;
}

function columnsFor(width: number): number {
  if (width >= 680) return 3;
  if (width >= 460) return 2;
  return 1;
}

const PAD = 20;
const SECTION_GAP = 18;
const HEADING_OFFSET = 14;
const BAR_H = 12;
const ROW_H = 50;
const ROW_GAP = 10;
const GAP = 2;
const MIN = 2;

function renderHeader(
  query: string,
  total: number,
  truncated: boolean,
  y: number,
): { svg: string; nextY: number } {
  const resultsWord = total === 1 ? "result" : "results";
  const title = `CVE Characteristics for "${query}" (${total}${truncated ? "+" : ""} ${resultsWord})`;
  const svg = `<text x="${PAD}" y="${y + 16}" fill="${TEXT_STRONG}" font-family="${FONT}" font-size="13" font-weight="600">${escapeXml(title)}</text>`;
  return { svg, nextY: y + 24 + SECTION_GAP };
}

function renderScoreHistogram(
  scoreDistribution: Record<string, number>,
  W: number,
  y: number,
): { svg: string; nextY: number } {
  const out: string[] = [];
  out.push(
    `<text x="${PAD}" y="${y + 10}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="10" letter-spacing="0.05em">BASE SCORE</text>`,
  );
  const top = y + HEADING_OFFSET + 6;
  const chartLeft = PAD + 28;
  const chartRight = W - PAD;
  const chartW = chartRight - chartLeft;
  const chartH = 130;
  const bottom = top + chartH - 18;

  const bins = BIN_DEFS.map((def) => ({
    label: def.label,
    count: def.floors.reduce(
      (s, f) => s + (scoreDistribution[String(f)] ?? 0),
      0,
    ),
    color: binColor(def.colorScore),
  }));
  const maxCount = Math.max(...bins.map((b) => b.count), 1);
  const ticks = niceTicks(maxCount, 4);
  const yMax = ticks[ticks.length - 1];

  // Grid + Y labels
  for (const t of ticks) {
    const ty = bottom - (t / yMax) * (bottom - top);
    out.push(
      `<line x1="${chartLeft}" y1="${ty.toFixed(2)}" x2="${chartRight}" y2="${ty.toFixed(2)}" stroke="${GRID_STROKE}" stroke-opacity="${GRID_OPACITY}" stroke-width="0.5" stroke-dasharray="2 3"/>`,
    );
    out.push(
      `<text x="${chartLeft - 4}" y="${(ty + 3).toFixed(2)}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="9" text-anchor="end">${t}</text>`,
    );
  }

  // Bars
  const binW = chartW / bins.length;
  const barW = binW * 0.82;
  for (let i = 0; i < bins.length; i++) {
    const b = bins[i];
    const h = b.count > 0 ? (b.count / yMax) * (bottom - top) : 0;
    const bx = chartLeft + binW * i + (binW - barW) / 2;
    const by = bottom - h;
    if (h > 0) {
      out.push(
        `<rect x="${fmt(bx)}" y="${fmt(by)}" width="${fmt(barW)}" height="${fmt(h)}" fill="${b.color}" stroke="${BAR_STROKE}" stroke-opacity="${BAR_STROKE_OPACITY}" stroke-width="0.5"/>`,
      );
    }
    out.push(
      `<text x="${fmt(chartLeft + binW * i + binW / 2)}" y="${fmt(bottom + 12)}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="9" text-anchor="middle">${b.label}</text>`,
    );
  }

  return { svg: out.join("\n"), nextY: top + chartH + SECTION_GAP };
}

function renderMetricRow(
  metric: MergedMetric,
  x: number,
  y: number,
  w: number,
  total: number,
): string {
  const out: string[] = [];
  const color = metricColor(metric.key);

  // Tag chip
  const keyW = metric.key.length * 6 + 8;
  out.push(
    `<rect x="${x}" y="${y}" width="${keyW}" height="14" rx="3" ry="3" fill="${color}" fill-opacity="0.13" stroke="${color}" stroke-opacity="0.27" stroke-width="1"/>`,
  );
  out.push(
    `<text x="${x + keyW / 2}" y="${y + 10}" fill="${color}" font-family="${FONT}" font-size="9" font-weight="700" text-anchor="middle" letter-spacing="0.05em">${escapeXml(metric.key)}</text>`,
  );

  // Title
  const titleX = x + keyW + 6;
  out.push(
    `<text x="${titleX}" y="${y + 10}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="11">${escapeXml(metric.title)}</text>`,
  );

  // Stacked bar — same gap-by-inset behavior as VectorDistribution.tsx so
  // 1-of-N slivers stay visible instead of getting wiped by the gap.
  const barY = y + 18;
  const domainMax = Math.max(total, metric.totalCount);
  let cursorX = x;
  for (const v of metric.values) {
    const empty = isEmptyValue(metric.key, v.value, v.label);
    const segW = (v.count / domainMax) * w;
    if (!empty && v.count > 0 && segW > 0) {
      const drawn = segW > GAP + MIN ? segW - GAP : Math.max(MIN, segW);
      const fillColor = shiftedColor(metric.key, v.value);
      const opacity = valueOpacity(metric.key, v.value);
      out.push(
        `<rect x="${fmt(cursorX)}" y="${barY}" width="${fmt(drawn)}" height="${BAR_H}" fill="${fillColor}" fill-opacity="${opacity.toFixed(2)}"/>`,
      );
    }
    cursorX += segW;
  }

  // Value labels under the bar — single text element, tspan-spaced.
  const labelY = barY + BAR_H + 10;
  const parts: string[] = [];
  for (let i = 0; i < metric.values.length; i++) {
    const v = metric.values[i];
    const empty = isEmptyValue(metric.key, v.value, v.label);
    const valColor = empty ? TEXT_MUTED : shiftedColor(metric.key, v.value);
    const valOpacity = empty ? 1 : valueOpacity(metric.key, v.value);
    const dx = i === 0 ? "" : ` dx="6"`;
    parts.push(
      `<tspan${dx} fill="${valColor}" fill-opacity="${valOpacity.toFixed(2)}">${escapeXml(v.value)}</tspan><tspan fill="${TEXT_MUTED}">:</tspan><tspan fill="${TEXT_STRONG}">${v.count}</tspan>`,
    );
  }
  out.push(
    `<text x="${x}" y="${labelY}" font-family="${FONT}" font-size="9">${parts.join("")}</text>`,
  );

  return out.join("\n");
}

function renderMetricGrid(
  merged: MergedMetric[],
  W: number,
  total: number,
  y: number,
): { svg: string; nextY: number } {
  const out: string[] = [];
  out.push(
    `<text x="${PAD}" y="${y + 10}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="10" letter-spacing="0.05em">VECTOR METRICS</text>`,
  );
  const startY = y + HEADING_OFFSET + 4;

  const cols = columnsFor(W);
  const gridW = W - 2 * PAD;
  const colGap = 16;
  const colW = (gridW - colGap * (cols - 1)) / cols;

  for (let i = 0; i < merged.length; i++) {
    const col = i % cols;
    const row = Math.floor(i / cols);
    const rx = PAD + col * (colW + colGap);
    const ry = startY + row * (ROW_H + ROW_GAP);
    out.push(renderMetricRow(merged[i], rx, ry, colW, total));
  }
  const rows = Math.ceil(merged.length / cols);
  const endY = startY + rows * (ROW_H + ROW_GAP) - ROW_GAP;
  return { svg: out.join("\n"), nextY: endY + SECTION_GAP };
}

function renderFooter(
  query: string,
  generatedAt: Date,
  W: number,
  y: number,
): { svg: string; nextY: number } {
  const text = `vulnsig.io · ${query} as of ${formatDate(generatedAt)}`;
  // Mirror the in-app product-search deep-link (see GlyphCard search-link).
  const href = `https://vulnsig.io/?tab=search&q=${encodeURIComponent(query)}&kind=product`;
  const svg = `<a xlink:href="${escapeXml(href)}" target="_blank"><text x="${W - PAD}" y="${y + 10}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="10" text-anchor="end">${escapeXml(text)}</text></a>`;
  return { svg, nextY: y + 16 };
}

export function renderDistributionSvg(input: RenderDistributionInput): string {
  const W = clamp(Math.round(input.width ?? 720), 320, 1600);
  const generatedAt = input.generatedAt ?? new Date();
  const merged = mergeVectorDistribution(input.vectorDistribution || {});
  const hasScore = Object.values(input.scoreDistribution || {}).some(
    (n) => n > 0,
  );
  const hasMetrics = merged.length > 0;

  const parts: string[] = [];
  let y = PAD;

  const header = renderHeader(input.query, input.total, input.truncated, y);
  parts.push(header.svg);
  y = header.nextY;

  if (!hasScore && !hasMetrics) {
    parts.push(
      `<text x="${W / 2}" y="${y + 20}" fill="${TEXT_BODY}" font-family="${FONT}" font-size="12" text-anchor="middle">No data available for this query</text>`,
    );
    y += 40 + SECTION_GAP;
  }

  if (hasScore) {
    const s = renderScoreHistogram(input.scoreDistribution || {}, W, y);
    parts.push(s.svg);
    y = s.nextY;
  }

  if (hasMetrics) {
    const m = renderMetricGrid(merged, W, input.total, y);
    parts.push(m.svg);
    y = m.nextY;
  }

  const footer = renderFooter(input.query, generatedAt, W, y);
  parts.push(footer.svg);
  y = footer.nextY;

  const H = y + PAD;

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
${parts.join("\n")}
</svg>`;
}
