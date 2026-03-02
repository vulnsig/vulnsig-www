export interface Callout {
  feature: string;
  label: string;
  anchor:
    | "center"
    | "top"
    | "top-right"
    | "right"
    | "bottom-right"
    | "bottom"
    | "bottom-left"
    | "left"
    | "top-left"
    | "inner-left"
    | "inner-right";
}

export interface AutoCallout extends Callout {
  metrics?: string[];
}

export function parseMetrics(vector: string): Record<string, string> {
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

const CIA_NAMES: Record<string, string> = {
  C: "Confidentiality",
  I: "Integrity",
  A: "Availability",
};
const LEVEL_NAMES: Record<string, string> = { H: "high", L: "low" };

export function formatImpact(
  pairs: [string, string][],
  metricPrefix = "",
): { label: string; metrics: string[] } {
  const active = pairs.filter(([, v]) => v !== "N");
  const metrics = active.map(([k]) => metricPrefix + k);
  const allSame = active.every(([, v]) => v === active[0][1]);
  if (active.length === pairs.length && allSame) {
    return {
      label: `All sectors ${LEVEL_NAMES[active[0][1]]}: Full CIA impact`,
      metrics,
    };
  }
  if (active.length === pairs.length) {
    const desc = active
      .map(([k, v]) => `${CIA_NAMES[k]} ${LEVEL_NAMES[v]}`)
      .join(", ");
    return { label: desc, metrics };
  }
  if (active.length === 0)
    return { label: "All sectors dark: No CIA impact", metrics: [] };
  const desc = active
    .map(([k, v]) => `${CIA_NAMES[k]} ${LEVEL_NAMES[v]}`)
    .join(", ");
  return { label: desc, metrics };
}

export function ciaCallout(
  m: Record<string, string>,
): { label: string; metrics: string[] } | null {
  // CVSS 4.0: VC/VI/VA + SC/SI/SA
  if (m.VC != null) {
    const vuln = formatImpact(
      [
        ["C", m.VC],
        ["I", m.VI],
        ["A", m.VA],
      ],
      "V",
    );
    const sub = formatImpact(
      [
        ["C", m.SC],
        ["I", m.SI],
        ["A", m.SA],
      ],
      "S",
    );
    const parts: string[] = [];
    if (vuln.metrics.length > 0) parts.push(`Vulnerable: ${vuln.label}`);
    if (sub.metrics.length > 0) parts.push(`Subsequent: ${sub.label}`);
    if (parts.length === 0)
      return { label: "All sectors dark: No CIA impact", metrics: [] };
    return {
      label: parts.join(" · "),
      metrics: [...vuln.metrics, ...sub.metrics],
    };
  }
  // CVSS 3.x: C/I/A
  if (m.C != null) {
    return formatImpact([
      ["C", m.C],
      ["I", m.I],
      ["A", m.A],
    ]);
  }
  return null;
}

export function autoCallouts(vector: string): AutoCallout[] {
  const m = parseMetrics(vector);
  const out: AutoCallout[] = [];

  if (m.AV && AV_LABELS[m.AV]) {
    out.push({
      feature: "star-points",
      label: AV_LABELS[m.AV],
      anchor: "center",
    });
  }
  if (m.AC && AC_LABELS[m.AC]) {
    out.push({
      feature: "star-shape",
      label: AC_LABELS[m.AC],
      anchor: m.AC === "L" ? "inner-right" : "inner-left",
    });
  }
  if (m.PR && PR_LABELS[m.PR]) {
    out.push({
      feature: "star-outline",
      label: PR_LABELS[m.PR],
      anchor: "left",
    });
  }
  if (m.UI && UI_LABELS[m.UI]) {
    const feature = m.UI === "N" ? "spikes" : "smooth-edge";
    out.push({ feature, label: UI_LABELS[m.UI], anchor: "top-right" });
  }
  const cia = ciaCallout(m);
  if (cia) {
    out.push({
      feature: "ring-brightness",
      label: cia.label,
      anchor: "right",
      metrics: cia.metrics,
    });
  }

  return out;
}
