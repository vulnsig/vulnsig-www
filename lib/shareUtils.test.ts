import { describe, it, expect } from "vitest";
import {
  getShareSentence,
  buildLandingUrl,
  buildShareText,
  buildPlatformUrls,
} from "./shareUtils";

// ---------------------------------------------------------------------------
// getShareSentence
// ---------------------------------------------------------------------------
describe("getShareSentence", () => {
  it("returns the first sentence when no productName given", () => {
    const desc =
      "A buffer overflow in libxml2 allows code execution. Other stuff here.";
    expect(getShareSentence(desc)).toBe(
      "A buffer overflow in libxml2 allows code execution.",
    );
  });

  it("returns the sentence containing the product name", () => {
    const desc =
      "Multiple issues exist. A use-after-free in OpenSSL allows memory disclosure. No further details.";
    expect(getShareSentence(desc, "OpenSSL")).toBe(
      "A use-after-free in OpenSSL allows memory disclosure.",
    );
  });

  it("product name match is case-insensitive", () => {
    const desc = "Unrelated sentence. A flaw in APACHE httpd allows bypass.";
    expect(getShareSentence(desc, "Apache httpd")).toBe(
      "A flaw in APACHE httpd allows bypass.",
    );
  });

  it("falls back to first sentence when product name not found", () => {
    const desc = "First sentence here. Second sentence here.";
    expect(getShareSentence(desc, "UnknownProduct")).toBe(
      "First sentence here.",
    );
  });

  it("returns the full description when no sentence boundaries exist", () => {
    const desc = "No punctuation at all here";
    expect(getShareSentence(desc)).toBe("No punctuation at all here");
  });

  it("does not split on periods within version numbers", () => {
    const desc =
      "Configuration issue in Java Management Extensions (JMX) in TIBCO BPM Enterprise version 4.x allows unauthorised access.";
    expect(getShareSentence(desc)).toBe(desc.trim());
  });

  it("does not split on periods within dotted identifiers", () => {
    const desc =
      "A flaw in com.example.Foo version 1.2.3 allows bypass. Second sentence.";
    expect(getShareSentence(desc)).toBe(
      "A flaw in com.example.Foo version 1.2.3 allows bypass.",
    );
  });
});

// ---------------------------------------------------------------------------
// buildShareText
// ---------------------------------------------------------------------------
describe("buildShareText", () => {
  it("formats the share text correctly", () => {
    expect(buildShareText("CVE-2025-1234", 9.8, "RCE in libxml2.")).toBe(
      "CVE-2025-1234 (CVSS 9.8): RCE in libxml2.",
    );
  });
});

// ---------------------------------------------------------------------------
// buildLandingUrl
// ---------------------------------------------------------------------------
describe("buildLandingUrl", () => {
  it("builds a clean URL with only the CVE ID", () => {
    const url = buildLandingUrl("CVE-2025-1234");
    expect(url).toBe("https://vulnsig.io/cve/CVE-2025-1234");
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/cve/CVE-2025-1234");
    expect(parsed.search).toBe("");
  });
});

// ---------------------------------------------------------------------------
// buildPlatformUrls
// ---------------------------------------------------------------------------
describe("buildPlatformUrls", () => {
  const shareText = "CVE-2025-1234 (CVSS 9.8) RCE in libxml2.";
  const landingUrl = "https://vulnsig.io/cve/CVE-2025-1234";
  const urls = buildPlatformUrls(
    shareText,
    landingUrl,
    "CVE-2025-1234",
    "RCE in libxml2.",
  );

  it("twitter URL contains encoded text and url params", () => {
    const parsed = new URL(urls.twitter);
    expect(parsed.hostname).toBe("twitter.com");
    expect(parsed.searchParams.get("text")).toBe(shareText);
    expect(parsed.searchParams.get("url")).toBe(landingUrl);
  });

  it("linkedin URL contains landing url", () => {
    const parsed = new URL(urls.linkedin);
    expect(parsed.hostname).toBe("www.linkedin.com");
    expect(parsed.searchParams.get("url")).toBe(landingUrl);
  });

  it("bluesky URL embeds shareText and landingUrl together in text param", () => {
    const parsed = new URL(urls.bluesky);
    expect(parsed.hostname).toBe("bsky.app");
    const text = parsed.searchParams.get("text")!;
    expect(text).toContain(shareText);
    expect(text).toContain(landingUrl);
  });

  it("reddit URL contains landing url and title", () => {
    const parsed = new URL(urls.reddit);
    expect(parsed.hostname).toBe("reddit.com");
    expect(parsed.searchParams.get("url")).toBe(landingUrl);
    expect(parsed.searchParams.get("title")).toContain("CVE-2025-1234");
  });

  it("email URL is a mailto with subject and body", () => {
    expect(urls.email.startsWith("mailto:")).toBe(true);
    expect(urls.email).toContain("CVE-2025-1234");
    expect(urls.email).toContain("VulnSig");
  });
});
