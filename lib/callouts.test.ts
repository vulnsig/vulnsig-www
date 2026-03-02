import { describe, it, expect } from "vitest";
import {
  parseMetrics,
  formatImpact,
  ciaCallout,
  autoCallouts,
} from "./callouts";

// ---------------------------------------------------------------------------
// parseMetrics
// ---------------------------------------------------------------------------
describe("parseMetrics", () => {
  it("parses a CVSS 3.1 vector", () => {
    const m = parseMetrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(m).toEqual({
      AV: "N",
      AC: "L",
      PR: "N",
      UI: "N",
      S: "U",
      C: "H",
      I: "H",
      A: "H",
    });
  });

  it("parses a CVSS 4.0 vector", () => {
    const m = parseMetrics(
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    );
    expect(m.AV).toBe("N");
    expect(m.AT).toBe("P");
    expect(m.VC).toBe("H");
    expect(m.SC).toBe("N");
  });

  it("excludes the CVSS version prefix", () => {
    const m = parseMetrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    expect(m).not.toHaveProperty("CVSS");
  });
});

// ---------------------------------------------------------------------------
// formatImpact
// ---------------------------------------------------------------------------
describe("formatImpact", () => {
  it("returns full impact when all are high", () => {
    const result = formatImpact([
      ["C", "H"],
      ["I", "H"],
      ["A", "H"],
    ]);
    expect(result.label).toBe("All sectors high: Full CIA impact");
    expect(result.metrics).toEqual(["C", "I", "A"]);
  });

  it("returns full impact when all are low", () => {
    const result = formatImpact([
      ["C", "L"],
      ["I", "L"],
      ["A", "L"],
    ]);
    expect(result.label).toBe("All sectors low: Full CIA impact");
  });

  it("returns no impact when all are none", () => {
    const result = formatImpact([
      ["C", "N"],
      ["I", "N"],
      ["A", "N"],
    ]);
    expect(result.label).toBe("All sectors dark: No CIA impact");
    expect(result.metrics).toEqual([]);
  });

  it("lists only non-N metrics", () => {
    const result = formatImpact([
      ["C", "H"],
      ["I", "N"],
      ["A", "N"],
    ]);
    expect(result.label).toBe("Confidentiality high");
    expect(result.metrics).toEqual(["C"]);
  });

  it("lists multiple active metrics", () => {
    const result = formatImpact([
      ["C", "H"],
      ["I", "H"],
      ["A", "N"],
    ]);
    expect(result.label).toBe("Confidentiality high, Integrity high");
    expect(result.metrics).toEqual(["C", "I"]);
  });

  it("handles mixed levels across all metrics", () => {
    const result = formatImpact([
      ["C", "H"],
      ["I", "L"],
      ["A", "H"],
    ]);
    expect(result.label).toBe(
      "Confidentiality high, Integrity low, Availability high",
    );
  });

  it("applies metric prefix", () => {
    const result = formatImpact(
      [
        ["C", "H"],
        ["I", "N"],
        ["A", "N"],
      ],
      "V",
    );
    expect(result.metrics).toEqual(["VC"]);
  });
});

// ---------------------------------------------------------------------------
// ciaCallout
// ---------------------------------------------------------------------------
describe("ciaCallout", () => {
  it("handles CVSS 3.x full impact", () => {
    const result = ciaCallout({ C: "H", I: "H", A: "H" });
    expect(result?.label).toBe("All sectors high: Full CIA impact");
    expect(result?.metrics).toEqual(["C", "I", "A"]);
  });

  it("handles CVSS 3.x partial impact", () => {
    const result = ciaCallout({ C: "H", I: "N", A: "N" });
    expect(result?.label).toBe("Confidentiality high");
    expect(result?.metrics).toEqual(["C"]);
  });

  it("handles CVSS 4.0 with only subsequent impact", () => {
    const result = ciaCallout({
      VC: "N",
      VI: "N",
      VA: "N",
      SC: "L",
      SI: "L",
      SA: "N",
    });
    expect(result?.label).toBe("Subsequent: Confidentiality low, Integrity low");
    expect(result?.metrics).toEqual(["SC", "SI"]);
  });

  it("handles CVSS 4.0 with both scopes", () => {
    const result = ciaCallout({
      VC: "H",
      VI: "H",
      VA: "H",
      SC: "H",
      SI: "H",
      SA: "H",
    });
    expect(result?.label).toContain("Vulnerable:");
    expect(result?.label).toContain("Subsequent:");
  });

  it("handles CVSS 4.0 with no impact at all", () => {
    const result = ciaCallout({
      VC: "N",
      VI: "N",
      VA: "N",
      SC: "N",
      SI: "N",
      SA: "N",
    });
    expect(result?.label).toBe("All sectors dark: No CIA impact");
    expect(result?.metrics).toEqual([]);
  });

  it("returns null when no CIA metrics present", () => {
    expect(ciaCallout({ AV: "N", AC: "L" })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// autoCallouts
// ---------------------------------------------------------------------------
describe("autoCallouts", () => {
  it("generates all 5 callouts for a complete CVSS 3.1 vector", () => {
    const callouts = autoCallouts(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    );
    const features = callouts.map((c) => c.feature);
    expect(features).toContain("star-points");
    expect(features).toContain("star-shape");
    expect(features).toContain("star-outline");
    expect(features).toContain("spikes");
    expect(features).toContain("ring-brightness");
  });

  it("uses correct AV labels", () => {
    const n = autoCallouts("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(n.find((c) => c.feature === "star-points")?.label).toContain(
      "8 points",
    );

    const l = autoCallouts("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(l.find((c) => c.feature === "star-points")?.label).toContain(
      "4 points",
    );
  });

  it("uses spikes feature for UI:N and smooth-edge for UI:R", () => {
    const n = autoCallouts("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(n.find((c) => c.feature === "spikes")).toBeDefined();

    const r = autoCallouts("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
    expect(r.find((c) => c.feature === "smooth-edge")).toBeDefined();
  });

  it("generates callouts for CVSS 4.0 vectors", () => {
    const callouts = autoCallouts(
      "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    );
    const features = callouts.map((c) => c.feature);
    expect(features).toContain("star-points");
    expect(features).toContain("ring-brightness");
  });

  it("includes correct CIA metrics for partial impact", () => {
    const callouts = autoCallouts(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    );
    const cia = callouts.find((c) => c.feature === "ring-brightness");
    expect(cia?.metrics).toEqual(["C", "I"]);
    expect(cia?.metrics).not.toContain("A");
  });
});
