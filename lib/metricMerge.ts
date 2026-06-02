// Impact metrics use H/L/N where "N" means *no impact*, so that segment is the
// genuinely empty case and should render as a blank slot. Exploitability
// metrics like AV/PR/UI/AT also use "None", but there "None" is a meaningful
// exploit characteristic (no privileges required, no user interaction needed)
// and should stay colored. "Not Defined" (E:X, E:ND) is treated as empty
// across the board.
export const IMPACT_METRICS = new Set([
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

export function isEmptyValue(
  metricKey: string,
  value: string,
  label: string,
): boolean {
  if (label === "Not Defined") return true;
  return IMPACT_METRICS.has(metricKey) && value === "N";
}

export interface MergedMetricValue {
  value: string;
  label: string;
  count: number;
}

export interface MergedMetric {
  key: string;
  title: string;
  values: MergedMetricValue[];
  totalCount: number;
  versionsCovered: string[];
}

type VectorDistribution = Record<string, Record<string, number>>;

const VALUE_LABELS: Record<string, Record<string, string>> = {
  AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
  AC: { L: "Low", M: "Medium", H: "High" },
  AT: { N: "None", P: "Present" },
  PR: { N: "None", L: "Low", H: "High" },
  UI: { N: "None", R: "Required", P: "Passive", A: "Active" },
  S: { U: "Unchanged", C: "Changed" },
  C: { H: "High", L: "Low", N: "None" },
  I: { H: "High", L: "Low", N: "None" },
  A: { H: "High", L: "Low", N: "None" },
  SC: { H: "High", L: "Low", N: "None" },
  SI: { H: "High", L: "Low", N: "None" },
  SA: { H: "High", L: "Low", N: "None" },
  E: {
    A: "Attacked",
    P: "PoC",
    U: "Unproven",
    X: "Not Defined",
    H: "High",
    F: "Functional",
    POC: "PoC",
    ND: "Not Defined",
  },
};

const VALUE_ORDER: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "M", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "R", "P", "A"],
  S: ["C", "U"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
  E: ["A", "H", "F", "P", "POC", "U", "X", "ND"],
};

// Map of which CVSS version each source key implies. Used to populate
// `versionsCovered` so the UI can footnote merged metrics.
const KEY_VERSIONS: Record<string, string[]> = {
  Au: ["2.0"],
  S: ["3.0", "3.1"],
  C: ["2.0", "3.0", "3.1"],
  I: ["2.0", "3.0", "3.1"],
  A: ["2.0", "3.0", "3.1"],
  PR: ["3.0", "3.1", "4.0"],
  AT: ["4.0"],
  VC: ["4.0"],
  VI: ["4.0"],
  VA: ["4.0"],
  SC: ["4.0"],
  SI: ["4.0"],
  SA: ["4.0"],
};

// Map a legacy CVSS 2.0 impact value (N/P/C) onto the 3.x H/L/N scheme so
// 2.0 and 3.x can be summed together. The mapping is the conventional one:
// 2.0 "None" ≈ 3.x "None", 2.0 "Partial" ≈ 3.x "Low", 2.0 "Complete" ≈ 3.x "High".
const CIA_2_TO_3: Record<string, string> = { N: "N", P: "L", C: "H" };

// Map a CVSS 2.0 Au value onto the 3.x PR scheme. Au:N (none) ≈ PR:N,
// Au:S (single instance) ≈ PR:L, Au:M (multiple) ≈ PR:H.
const AU_TO_PR: Record<string, string> = { N: "N", S: "L", M: "H" };

function emptyBucket(order: string[]): Record<string, number> {
  const b: Record<string, number> = {};
  for (const v of order) b[v] = 0;
  return b;
}

function addCounts(
  bucket: Record<string, number>,
  source: Record<string, number> | undefined,
  remap?: Record<string, string>,
) {
  if (!source) return;
  for (const [val, count] of Object.entries(source)) {
    const mapped = remap ? remap[val] : val;
    if (mapped == null) continue;
    bucket[mapped] = (bucket[mapped] ?? 0) + count;
  }
}

function buildMetric(
  key: string,
  title: string,
  bucket: Record<string, number>,
  order: string[],
  versionsCovered: string[],
): MergedMetric | null {
  const values: MergedMetricValue[] = [];
  let total = 0;
  for (const v of order) {
    const count = bucket[v] ?? 0;
    if (count > 0) {
      values.push({
        value: v,
        label: VALUE_LABELS[key]?.[v] ?? v,
        count,
      });
      total += count;
    }
  }
  if (total === 0) return null;
  return {
    key,
    title,
    values,
    totalCount: total,
    versionsCovered,
  };
}

function collectVersions(
  vd: VectorDistribution,
  sourceKeys: string[],
): string[] {
  const set = new Set<string>();
  for (const k of sourceKeys) {
    if (!vd[k]) continue;
    const versions = KEY_VERSIONS[k];
    if (versions) {
      for (const v of versions) set.add(v);
    } else {
      // Keys without an entry in KEY_VERSIONS are universal (AV/AC/UI/E) —
      // we can't tell which version contributed from the payload alone, so
      // we don't add anything. The footnote is reserved for cross-version
      // merges where the merge itself is the interesting fact.
    }
  }
  return Array.from(set).sort();
}

export function mergeVectorDistribution(
  vd: VectorDistribution,
): MergedMetric[] {
  const out: MergedMetric[] = [];

  // AV — identity, all versions
  if (vd.AV) {
    const bucket = emptyBucket(VALUE_ORDER.AV);
    addCounts(bucket, vd.AV);
    const m = buildMetric("AV", "Attack Vector", bucket, VALUE_ORDER.AV, []);
    if (m) out.push(m);
  }

  // AC — identity, 2.0 contributes M
  if (vd.AC) {
    const bucket = emptyBucket(VALUE_ORDER.AC);
    addCounts(bucket, vd.AC);
    const m = buildMetric(
      "AC",
      "Attack Complexity",
      bucket,
      VALUE_ORDER.AC,
      [],
    );
    if (m) out.push(m);
  }

  // AT — 4.0 only
  if (vd.AT) {
    const bucket = emptyBucket(VALUE_ORDER.AT);
    addCounts(bucket, vd.AT);
    const m = buildMetric("AT", "Attack Requirements", bucket, VALUE_ORDER.AT, [
      "4.0",
    ]);
    if (m) out.push(m);
  }

  // PR — merges Au (2.0)
  if (vd.PR || vd.Au) {
    const bucket = emptyBucket(VALUE_ORDER.PR);
    addCounts(bucket, vd.PR);
    addCounts(bucket, vd.Au, AU_TO_PR);
    const m = buildMetric(
      "PR",
      vd.Au ? "Privileges / Auth" : "Privileges Required",
      bucket,
      VALUE_ORDER.PR,
      collectVersions(vd, ["PR", "Au"]),
    );
    if (m) out.push(m);
  }

  // UI — identity
  if (vd.UI) {
    const bucket = emptyBucket(VALUE_ORDER.UI);
    addCounts(bucket, vd.UI);
    const m = buildMetric("UI", "User Interaction", bucket, VALUE_ORDER.UI, []);
    if (m) out.push(m);
  }

  // S — 3.x only
  if (vd.S) {
    const bucket = emptyBucket(VALUE_ORDER.S);
    addCounts(bucket, vd.S);
    const m = buildMetric("S", "Scope", bucket, VALUE_ORDER.S, ["3.0", "3.1"]);
    if (m) out.push(m);
  }

  // C / VC merge (vulnerable system confidentiality)
  if (vd.C || vd.VC) {
    const bucket = emptyBucket(VALUE_ORDER.C);
    addCounts(bucket, vd.C, isLikely2Impact(vd.C) ? CIA_2_TO_3 : undefined);
    addCounts(bucket, vd.VC);
    const m = buildMetric(
      "C",
      vd.VC ? "Confidentiality (vulnerable)" : "Confidentiality",
      bucket,
      VALUE_ORDER.C,
      collectVersions(vd, ["C", "VC"]),
    );
    if (m) out.push(m);
  }

  // I / VI merge
  if (vd.I || vd.VI) {
    const bucket = emptyBucket(VALUE_ORDER.I);
    addCounts(bucket, vd.I, isLikely2Impact(vd.I) ? CIA_2_TO_3 : undefined);
    addCounts(bucket, vd.VI);
    const m = buildMetric(
      "I",
      vd.VI ? "Integrity (vulnerable)" : "Integrity",
      bucket,
      VALUE_ORDER.I,
      collectVersions(vd, ["I", "VI"]),
    );
    if (m) out.push(m);
  }

  // A / VA merge
  if (vd.A || vd.VA) {
    const bucket = emptyBucket(VALUE_ORDER.A);
    addCounts(bucket, vd.A, isLikely2Impact(vd.A) ? CIA_2_TO_3 : undefined);
    addCounts(bucket, vd.VA);
    const m = buildMetric(
      "A",
      vd.VA ? "Availability (vulnerable)" : "Availability",
      bucket,
      VALUE_ORDER.A,
      collectVersions(vd, ["A", "VA"]),
    );
    if (m) out.push(m);
  }

  // 4.0 subsequent system impacts
  for (const k of ["SC", "SI", "SA"] as const) {
    if (vd[k]) {
      const bucket = emptyBucket(VALUE_ORDER[k]);
      addCounts(bucket, vd[k]);
      const title =
        k === "SC"
          ? "Confidentiality (subsequent)"
          : k === "SI"
            ? "Integrity (subsequent)"
            : "Availability (subsequent)";
      const m = buildMetric(k, title, bucket, VALUE_ORDER[k], ["4.0"]);
      if (m) out.push(m);
    }
  }

  // E — exploit maturity; render whatever the backend returned, union of value sets
  if (vd.E) {
    const bucket = emptyBucket(VALUE_ORDER.E);
    addCounts(bucket, vd.E);
    const m = buildMetric("E", "Exploit Maturity", bucket, VALUE_ORDER.E, []);
    if (m) out.push(m);
  }

  // Drop metrics whose entire result set sits in their "empty" value(s) —
  // an impact metric where every result is N (no impact) or E where every
  // result is X/ND (not defined) carries no signal. The matching segments
  // already render transparent, so the row would be a blank slot anyway.
  return out.filter((m) => !isAllEmpty(m));
}

function isAllEmpty(metric: MergedMetric): boolean {
  if (IMPACT_METRICS.has(metric.key)) {
    return metric.values.every((v) => v.value === "N");
  }
  if (metric.key === "E") {
    return metric.values.every((v) => v.value === "X" || v.value === "ND");
  }
  return false;
}

// CVSS 2.0 impact uses N/P/C while 3.x uses H/L/N. The presence of "P" or "C"
// in a C/I/A bucket signals a 2.0 payload that needs remapping into the 3.x
// scheme before being summed.
function isLikely2Impact(source: Record<string, number> | undefined): boolean {
  if (!source) return false;
  return source.P != null || source.C != null;
}

// Per-metric "scariness" ranking, 0 = safest (yellow) → 10 = scariest (dark red).
// Used by valueColor() to map (metricKey, value) onto a point on the vulnsig
// glyph palette. Lower index in the list = scarier.
const SCARINESS_ORDER: Record<string, string[]> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "M", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "R", "P", "A"],
  S: ["C", "U"],
  C: ["H", "L", "N"],
  I: ["H", "L", "N"],
  A: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
  E: ["A", "H", "F", "P", "POC", "U", "X", "ND"],
};

// Map a (metricKey, value) onto a hue offset in degrees, centered on the
// metric's tag color. The scariest value sits at -HUE_SPREAD and the safest
// at +HUE_SPREAD; intermediates are linearly spaced. Paired with the metric's
// tag color, this lets each metric's bars stay visually associated with its
// tag while still letting individual values be distinguishable by hue rather
// than just by intensity.
const HUE_SPREAD = 10;

export function valueHueOffset(metricKey: string, value: string): number {
  const order = SCARINESS_ORDER[metricKey];
  if (!order) return 0;
  const idx = order.indexOf(value);
  if (idx < 0) return 0;
  const denom = Math.max(1, order.length - 1);
  return -HUE_SPREAD * 0.5 + (idx / denom) * (1.5 * HUE_SPREAD);
}

// A modest opacity spread layered on top of valueHueOffset — the scariest
// value renders at full strength, the safest fades a little. Together with
// the hue offset this gives bars two cues (hue + intensity) without leaning
// on either one too hard.
const OPACITY_MAX = 0.95;
const OPACITY_MIN = 0.4;

export function valueOpacity(metricKey: string, value: string): number {
  const order = SCARINESS_ORDER[metricKey];
  if (!order) return OPACITY_MAX;
  const idx = order.indexOf(value);
  if (idx < 0) return OPACITY_MAX;
  const denom = Math.max(1, order.length - 1);
  return OPACITY_MAX - (idx / denom) * (OPACITY_MAX - OPACITY_MIN);
}
