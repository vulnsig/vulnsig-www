/**
 * CVSS version detection and normalization helpers.
 *
 * vulnsig 2.0 keeps these internal, so the www app re-implements the same
 * detection rules. CVSS 2.0 vectors arrive in two forms — bare
 * (`AV:N/AC:M/Au:N/C:N/I:N/A:P`) and prefixed (`CVSS:2.0/AV:N/...`). The app
 * normalizes everything to the prefixed form before storing or rendering so
 * the rest of the codebase can rely on a single shape.
 */

export type CvssVersion = "2.0" | "3.0" | "3.1" | "4.0";

const V2_PREFIX = "CVSS:2.0/";

function v2Body(vector: string): string {
  return vector
    .trim()
    .replace(/^\(/, "")
    .replace(/\)$/, "")
    .replace(/^CVSS:2\.0\//, "")
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");
}

function looksLikeCvss2(vector: string): boolean {
  const tokens = new Set<string>();
  for (const part of v2Body(vector).split("/")) {
    const key = part.split(":")[0];
    if (key) tokens.add(key);
  }
  return tokens.has("Au") && tokens.has("AV") && tokens.has("AC");
}

export function detectCvssVersion(vector: string): CvssVersion | null {
  if (vector.startsWith("CVSS:3.1/")) return "3.1";
  if (vector.startsWith("CVSS:3.0/")) return "3.0";
  if (vector.startsWith("CVSS:4.0/")) return "4.0";
  if (vector.startsWith("CVSS:2.0/")) return "2.0";
  if (!vector.startsWith("CVSS:") && looksLikeCvss2(vector)) return "2.0";
  return null;
}

export function isCvss2(vector: string): boolean {
  return detectCvssVersion(vector) === "2.0";
}

/**
 * Promote a bare CVSS 2.0 vector to its `CVSS:2.0/`-prefixed form. Leaves
 * already-prefixed vectors and non-CVSS-2 vectors unchanged.
 */
export function normalizeVector(vector: string): string {
  if (!vector) return vector;
  if (vector.startsWith("CVSS:")) return vector;
  if (!looksLikeCvss2(vector)) return vector;
  return `${V2_PREFIX}${v2Body(vector)}`;
}
