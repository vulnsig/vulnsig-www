import { describe, it, expect } from "vitest";
import { encodeVector, decodeVector } from "./vectorUrl";

const STANDARD =
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const COMPACT =
  "CVSS.4.0-AV.N-AC.L-AT.N-PR.N-UI.N-VC.H-VI.H-VA.H-SC.N-SI.N-SA.N";

const STANDARD_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const COMPACT_31 = "CVSS.3.1-AV.N-AC.L-PR.N-UI.N-S.U-C.H-I.H-A.H";

const STANDARD_20 = "CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:N/A:P";
const COMPACT_20 = "CVSS.2.0-AV.N-AC.M-Au.N-C.N-I.N-A.P";

describe("encodeVector", () => {
  it("encodes CVSS 4.0 vector", () => {
    expect(encodeVector(STANDARD)).toBe(COMPACT);
  });

  it("encodes CVSS 3.1 vector", () => {
    expect(encodeVector(STANDARD_31)).toBe(COMPACT_31);
  });

  it("encodes CVSS 2.0 vector", () => {
    expect(encodeVector(STANDARD_20)).toBe(COMPACT_20);
  });
});

describe("decodeVector", () => {
  it("decodes compact CVSS 4.0 vector", () => {
    expect(decodeVector(COMPACT)).toBe(STANDARD);
  });

  it("decodes compact CVSS 3.1 vector", () => {
    expect(decodeVector(COMPACT_31)).toBe(STANDARD_31);
  });

  it("passes through already-standard vector unchanged", () => {
    expect(decodeVector(STANDARD)).toBe(STANDARD);
    expect(decodeVector(STANDARD_31)).toBe(STANDARD_31);
  });

  it("decodes compact CVSS 2.0 vector", () => {
    expect(decodeVector(COMPACT_20)).toBe(STANDARD_20);
  });

  it("round-trips correctly", () => {
    expect(decodeVector(encodeVector(STANDARD))).toBe(STANDARD);
    expect(decodeVector(encodeVector(STANDARD_31))).toBe(STANDARD_31);
    expect(decodeVector(encodeVector(STANDARD_20))).toBe(STANDARD_20);
  });
});
