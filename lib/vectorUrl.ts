/**
 * Compact URL encoding for CVSS vectors.
 *
 * CVSS vectors only use letters, digits, ":", and "/". Neither "." nor "-"
 * ever appears in a valid vector, so the mapping is lossless and unambiguous.
 *
 *   ":"  →  "."   (unreserved in URLs, no percent-encoding)
 *   "/"  →  "-"   (unreserved in URLs, no percent-encoding)
 *
 * Example:
 *   CVSS:4.0/AV:N/AC:L  →  CVSS.4.0-AV.N-AC.L
 */
export function encodeVector(vector: string): string {
  return vector.replace(/:/g, ".").replace(/\//g, "-");
}

/**
 * Decode a vector that may be in compact form ("CVSS.…") or standard form
 * ("CVSS:…"). Percent-encoded vectors are decoded automatically by the URL
 * parser before reaching this function, so only these two cases are needed.
 */
export function decodeVector(raw: string): string {
  if (!raw.startsWith("CVSS.")) return raw;
  // Protect digit.digit sequences (version numbers like 3.1, 4.0) before
  // replacing remaining dots with colons.
  return raw
    .replace(/(\d)\.(\d)/g, "$1\x00$2")
    .replace(/\./g, ":")
    .replace(/-/g, "/")
    .replace(/\x00/g, ".");
}
