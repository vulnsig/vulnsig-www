import { describe, it, expect } from "vitest";
import {
  mergeVectorDistribution,
  valueHueOffset,
  valueOpacity,
} from "./metricMerge";

describe("mergeVectorDistribution", () => {
  it("returns empty array for empty input", () => {
    expect(mergeVectorDistribution({})).toEqual([]);
  });

  it("emits AV/AC/UI as identity charts when present", () => {
    const out = mergeVectorDistribution({
      AV: { N: 100, L: 20 },
      AC: { L: 80, H: 40 },
      UI: { N: 90, R: 30 },
    });
    expect(out.map((m) => m.key)).toEqual(["AV", "AC", "UI"]);
    const av = out.find((m) => m.key === "AV")!;
    expect(av.values).toEqual([
      { value: "N", label: "Network", count: 100 },
      { value: "L", label: "Local", count: 20 },
    ]);
    expect(av.totalCount).toBe(120);
    expect(av.versionsCovered).toEqual([]);
  });

  it("merges Au (2.0) into PR with Au:N->PR:N, Au:S->PR:L, Au:M->PR:H", () => {
    const out = mergeVectorDistribution({
      PR: { N: 10, L: 5, H: 2 },
      Au: { N: 4, S: 3, M: 1 },
    });
    const pr = out.find((m) => m.key === "PR")!;
    expect(pr.title).toBe("Privileges / Auth");
    const counts = Object.fromEntries(pr.values.map((v) => [v.value, v.count]));
    expect(counts).toEqual({ N: 14, L: 8, H: 3 });
    expect(pr.versionsCovered).toContain("2.0");
    expect(pr.versionsCovered).toContain("3.0");
    expect(pr.versionsCovered).toContain("3.1");
    expect(pr.versionsCovered).toContain("4.0");
  });

  it("emits PR alone (no Au footnote) when only PR is present", () => {
    const out = mergeVectorDistribution({ PR: { N: 10, L: 5 } });
    const pr = out.find((m) => m.key === "PR")!;
    expect(pr.title).toBe("Privileges Required");
  });

  it("merges 4.0 VC into C and adds versionsCovered", () => {
    const out = mergeVectorDistribution({
      C: { H: 10, L: 5, N: 2 },
      VC: { H: 3, L: 1, N: 0 },
    });
    const c = out.find((m) => m.key === "C")!;
    expect(c.title).toBe("Confidentiality (vulnerable)");
    const counts = Object.fromEntries(c.values.map((v) => [v.value, v.count]));
    expect(counts).toEqual({ H: 13, L: 6, N: 2 });
    expect(c.versionsCovered).toEqual(
      expect.arrayContaining(["2.0", "3.0", "3.1", "4.0"]),
    );
  });

  it("remaps 2.0 C:P/C:C onto the 3.x H/L/N scheme", () => {
    const out = mergeVectorDistribution({
      C: { N: 5, P: 4, C: 3 },
    });
    const c = out.find((m) => m.key === "C")!;
    const counts = Object.fromEntries(c.values.map((v) => [v.value, v.count]));
    expect(counts).toEqual({ H: 3, L: 4, N: 5 });
  });

  it("emits S only when present (3.x-only)", () => {
    const a = mergeVectorDistribution({ AV: { N: 1 } });
    expect(a.find((m) => m.key === "S")).toBeUndefined();
    const b = mergeVectorDistribution({ S: { U: 10, C: 4 } });
    expect(b.find((m) => m.key === "S")?.totalCount).toBe(14);
  });

  it("emits AT/SC/SI/SA only when present (4.0-only)", () => {
    const out = mergeVectorDistribution({
      AT: { N: 8, P: 2 },
      SC: { H: 1, L: 2, N: 3 },
    });
    expect(out.find((m) => m.key === "AT")?.versionsCovered).toEqual(["4.0"]);
    expect(out.find((m) => m.key === "SC")?.totalCount).toBe(6);
    expect(out.find((m) => m.key === "SI")).toBeUndefined();
  });

  it("preserves canonical key order in output", () => {
    const out = mergeVectorDistribution({
      SA: { H: 1 },
      AC: { L: 1 },
      I: { H: 1 },
      AV: { N: 1 },
      PR: { N: 1 },
    });
    expect(out.map((m) => m.key)).toEqual(["AV", "AC", "PR", "I", "SA"]);
  });

  it("drops empty values from the value list", () => {
    const out = mergeVectorDistribution({ AV: { N: 5, A: 0, L: 0 } });
    expect(out[0].values.map((v) => v.value)).toEqual(["N"]);
  });

  it("drops C/I/A/SC/SI/SA when every result is in the N (no impact) bucket", () => {
    const out = mergeVectorDistribution({
      AV: { N: 10 },
      C: { N: 10 },
      I: { N: 10 },
      A: { N: 10 },
      SC: { N: 10 },
      SI: { N: 10 },
      SA: { N: 10 },
    });
    expect(out.map((m) => m.key)).toEqual(["AV"]);
  });

  it("keeps C if at least one non-N value appears", () => {
    const out = mergeVectorDistribution({ C: { N: 10, L: 1 } });
    expect(out.find((m) => m.key === "C")).toBeDefined();
  });

  it("drops impact metric even when merged from VC", () => {
    const out = mergeVectorDistribution({
      C: { N: 5 },
      VC: { N: 5 },
    });
    expect(out.find((m) => m.key === "C")).toBeUndefined();
  });

  it("drops E when every result is Not Defined (X or ND)", () => {
    const onlyX = mergeVectorDistribution({ E: { X: 50 } });
    expect(onlyX.find((m) => m.key === "E")).toBeUndefined();
    const onlyND = mergeVectorDistribution({ E: { ND: 50 } });
    expect(onlyND.find((m) => m.key === "E")).toBeUndefined();
    const mixed = mergeVectorDistribution({ E: { X: 10, ND: 10 } });
    expect(mixed.find((m) => m.key === "E")).toBeUndefined();
  });

  it("keeps E when any non-Not-Defined value appears", () => {
    const out = mergeVectorDistribution({ E: { X: 10, A: 1 } });
    expect(out.find((m) => m.key === "E")).toBeDefined();
  });
});

describe("valueHueOffset", () => {
  it("returns a negative offset for the scariest value and positive for the safest", () => {
    // Impact metrics: H is scariest, N is safest. L sits between them.
    const h = valueHueOffset("C", "H");
    const l = valueHueOffset("C", "L");
    const n = valueHueOffset("C", "N");
    expect(h).toBeLessThan(0);
    expect(n).toBeGreaterThan(0);
    expect(l).toBeGreaterThan(h);
    expect(l).toBeLessThan(n);
  });

  it("monotonically increases from scariest to safest along AV", () => {
    const n = valueHueOffset("AV", "N");
    const a = valueHueOffset("AV", "A");
    const l = valueHueOffset("AV", "L");
    const p = valueHueOffset("AV", "P");
    expect(n).toBeLessThan(a);
    expect(a).toBeLessThan(l);
    expect(l).toBeLessThan(p);
  });

  it("returns 0 for unknown metrics or values", () => {
    expect(valueHueOffset("ZZ", "X")).toBe(0);
    expect(valueHueOffset("AV", "ZZ")).toBe(0);
  });
});

describe("valueOpacity", () => {
  it("returns higher opacity for scarier values within a metric", () => {
    expect(valueOpacity("C", "H")).toBeGreaterThan(valueOpacity("C", "L"));
    expect(valueOpacity("C", "L")).toBeGreaterThan(valueOpacity("C", "N"));
    expect(valueOpacity("AV", "N")).toBeGreaterThan(valueOpacity("AV", "P"));
  });

  it("returns a value in [0, 1]", () => {
    const o = valueOpacity("AV", "L");
    expect(o).toBeGreaterThan(0);
    expect(o).toBeLessThanOrEqual(1);
  });
});
