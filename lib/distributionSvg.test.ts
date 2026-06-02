import { describe, it, expect } from "vitest";
import { renderDistributionSvg } from "./distributionSvg";

const FIXED_DATE = new Date("2026-06-01T12:00:00Z");

describe("renderDistributionSvg", () => {
  it("includes the query, total, and pluralized 'results' in the title", () => {
    const svg = renderDistributionSvg({
      query: "openssl",
      total: 457,
      truncated: false,
      scoreDistribution: { "7": 100 },
      vectorDistribution: { AV: { N: 100 } },
      generatedAt: FIXED_DATE,
    });
    // Quotes are XML-escaped in attribute-safe form.
    expect(svg).toContain(
      "CVE Characteristics for &quot;openssl&quot; (457 results)",
    );
  });

  it("uses singular 'result' for total=1 and a '+' suffix when truncated", () => {
    const svg = renderDistributionSvg({
      query: "foo",
      total: 1,
      truncated: true,
      scoreDistribution: { "9": 1 },
      vectorDistribution: { AV: { N: 1 } },
      generatedAt: FIXED_DATE,
    });
    expect(svg).toContain("1+ result");
  });

  it("emits an attribution footer linking back to vulnsig.io", () => {
    const svg = renderDistributionSvg({
      query: "openssl",
      total: 10,
      truncated: false,
      scoreDistribution: { "5": 10 },
      vectorDistribution: { AV: { N: 10 } },
      generatedAt: FIXED_DATE,
    });
    expect(svg).toContain("vulnsig.io · openssl as of 2026-06-01");
    expect(svg).toContain(
      'xlink:href="https://vulnsig.io/?tab=search&amp;q=openssl&amp;kind=product"',
    );
  });

  it("draws a 1-of-462 sliver with the MIN clamp so it stays visible", () => {
    // 1 / 462 over a column width ~213px (720px / 3 cols - paddings) is well
    // under 2px — the inset trick would wipe it out. The renderer should
    // clamp to MIN so a non-zero rect width is emitted.
    const svg = renderDistributionSvg({
      query: "openssl",
      total: 462,
      truncated: false,
      scoreDistribution: { "7": 462 },
      // AT only appears in CVSS 4.0; one P out of 462 mimics the real case.
      vectorDistribution: { AT: { N: 461, P: 1 } },
      width: 720,
      generatedAt: FIXED_DATE,
    });
    // Extract rect widths for the AT row's segments. With domainMax=462 and
    // colW~213px, AT:P would naturally be ~0.46px — the clamp brings it to 2.
    const matches = [...svg.matchAll(/<rect[^>]*width="([\d.]+)"/g)].map((m) =>
      Number(m[1]),
    );
    // Some narrow but non-zero rect must exist (the sliver).
    expect(matches.some((w) => w >= 2 && w <= 3)).toBe(true);
  });

  it("renders a graceful 'no data' message when distributions are empty", () => {
    const svg = renderDistributionSvg({
      query: "nothing-matches",
      total: 0,
      truncated: false,
      scoreDistribution: {},
      vectorDistribution: {},
      generatedAt: FIXED_DATE,
    });
    expect(svg).toContain("No data available for this query");
    expect(svg).not.toContain("BASE SCORE");
    expect(svg).not.toContain("VECTOR METRICS");
  });

  it("escapes special characters in the query (XSS safety)", () => {
    const svg = renderDistributionSvg({
      query: "<script>alert(1)</script>",
      total: 10,
      truncated: false,
      scoreDistribution: { "5": 10 },
      vectorDistribution: { AV: { N: 10 } },
      generatedAt: FIXED_DATE,
    });
    expect(svg).not.toContain("<script>");
    expect(svg).toContain("&lt;script&gt;");
  });

  it("clamps width to 320–1600", () => {
    const small = renderDistributionSvg({
      query: "x",
      total: 1,
      truncated: false,
      scoreDistribution: { "5": 1 },
      vectorDistribution: { AV: { N: 1 } },
      width: 10,
      generatedAt: FIXED_DATE,
    });
    expect(small).toMatch(/width="320"/);

    const huge = renderDistributionSvg({
      query: "x",
      total: 1,
      truncated: false,
      scoreDistribution: { "5": 1 },
      vectorDistribution: { AV: { N: 1 } },
      width: 9999,
      generatedAt: FIXED_DATE,
    });
    expect(huge).toMatch(/width="1600"/);
  });

  it("starts with the XML declaration and an <svg> root", () => {
    const svg = renderDistributionSvg({
      query: "x",
      total: 1,
      truncated: false,
      scoreDistribution: { "5": 1 },
      vectorDistribution: { AV: { N: 1 } },
      generatedAt: FIXED_DATE,
    });
    expect(svg.startsWith("<?xml")).toBe(true);
    expect(svg).toContain("<svg ");
    expect(svg.trimEnd().endsWith("</svg>")).toBe(true);
  });
});
