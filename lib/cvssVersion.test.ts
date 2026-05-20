import { describe, it, expect } from "vitest";
import { detectCvssVersion, isCvss2, normalizeVector } from "./cvssVersion";

const V2_BARE = "AV:N/AC:M/Au:N/C:N/I:N/A:P";
const V2_PREFIXED = "CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:N/A:P";
const V2_BARE_2 = "AV:N/AC:L/Au:N/C:N/I:N/A:P";

const V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

describe("detectCvssVersion", () => {
  it("detects prefixed versions", () => {
    expect(detectCvssVersion(V2_PREFIXED)).toBe("2.0");
    expect(detectCvssVersion(V30)).toBe("3.0");
    expect(detectCvssVersion(V31)).toBe("3.1");
    expect(detectCvssVersion(V40)).toBe("4.0");
  });

  it("detects bare CVSS 2.0", () => {
    expect(detectCvssVersion(V2_BARE)).toBe("2.0");
    expect(detectCvssVersion(V2_BARE_2)).toBe("2.0");
  });

  it("rejects unrecognized input", () => {
    expect(detectCvssVersion("")).toBeNull();
    expect(detectCvssVersion("nonsense")).toBeNull();
    // Missing the 2.0-only Au token — not enough to claim CVSS 2.0.
    expect(detectCvssVersion("AV:N/AC:L/C:N")).toBeNull();
  });
});

describe("isCvss2", () => {
  it("returns true for both 2.0 forms", () => {
    expect(isCvss2(V2_BARE)).toBe(true);
    expect(isCvss2(V2_PREFIXED)).toBe(true);
  });

  it("returns false for other versions", () => {
    expect(isCvss2(V31)).toBe(false);
    expect(isCvss2(V40)).toBe(false);
  });
});

describe("normalizeVector", () => {
  it("prefixes bare CVSS 2.0 vectors", () => {
    expect(normalizeVector(V2_BARE)).toBe(V2_PREFIXED);
  });

  it("leaves prefixed CVSS 2.0 vectors unchanged", () => {
    expect(normalizeVector(V2_PREFIXED)).toBe(V2_PREFIXED);
  });

  it("leaves 3.x and 4.0 vectors unchanged", () => {
    expect(normalizeVector(V30)).toBe(V30);
    expect(normalizeVector(V31)).toBe(V31);
    expect(normalizeVector(V40)).toBe(V40);
  });

  it("passes through empty and unrecognized strings", () => {
    expect(normalizeVector("")).toBe("");
    expect(normalizeVector("nonsense")).toBe("nonsense");
  });

  it("strips parens and stray slashes around bare 2.0", () => {
    expect(normalizeVector("(AV:N/AC:M/Au:N/C:N/I:N/A:P)")).toBe(V2_PREFIXED);
    expect(normalizeVector("/AV:N/AC:M/Au:N/C:N/I:N/A:P/")).toBe(V2_PREFIXED);
  });
});
