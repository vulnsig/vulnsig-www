// A period is "internal" (not a sentence boundary) when immediately followed
// by a non-whitespace character, e.g. "4.x", "v2.0", "e.g.".
const SENTENCE_RE = /(?:[^.!?]|\.(?=\S))+[.!?]+/g;

export function getShareSentence(
  description: string,
  productName?: string,
): string {
  const matches = description.match(SENTENCE_RE) ?? [];
  if (productName) {
    const lower = productName.toLowerCase();
    const found = matches.find((s) => s.toLowerCase().includes(lower));
    if (found) return found.trim();
  }
  return (matches[0] ?? description).trim();
}

export function buildLandingUrl(
  cveId: string,
  vector: string,
  score: number,
  description: string,
  productName?: string,
): string {
  const sentence = getShareSentence(description, productName);
  const d = sentence.length > 150 ? sentence.slice(0, 150) + "…" : sentence;
  const params = new URLSearchParams({ v: vector, s: String(score), d });
  return `https://vulnsig.io/cve/${cveId}?${params}`;
}

export function buildShareText(
  cveId: string,
  score: number,
  sentence: string,
): string {
  return `${cveId} (CVSS ${score}) — ${sentence}`;
}

export function buildPlatformUrls(
  shareText: string,
  landingUrl: string,
  cveId: string,
  sentence: string,
) {
  return {
    twitter: `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(landingUrl)}`,
    linkedin: `https://www.linkedin.com/shareArticle?mini=true&url=${encodeURIComponent(landingUrl)}&title=${encodeURIComponent(cveId)}&summary=${encodeURIComponent(sentence)}`,
    bluesky: `https://bsky.app/intent/compose?text=${encodeURIComponent(`${shareText} ${landingUrl}`)}`,
    reddit: `https://reddit.com/submit?url=${encodeURIComponent(landingUrl)}&title=${encodeURIComponent(`${cveId} — ${sentence}`)}`,
    email: `mailto:?subject=${encodeURIComponent(`${cveId} — VulnSig`)}&body=${encodeURIComponent(`${shareText}\n\n${landingUrl}`)}`,
  };
}

export function openShareWindow(url: string, width = 600, height = 500): void {
  window.open(
    url,
    "_blank",
    `noopener,noreferrer,width=${width},height=${height}`,
  );
}
