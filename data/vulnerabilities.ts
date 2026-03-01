export interface Callout {
  feature: string;
  label: string;
  anchor: "center" | "top" | "top-right" | "right" | "bottom-right" | "bottom" | "bottom-left" | "left" | "top-left" | "inner-left" | "inner-right";
}

export interface Vulnerability {
  name: string;
  cve: string | null;
  vector: string;
  description: string;
  callouts: Callout[] | null;
}

export const VULNERABILITIES: Vulnerability[] = [
  {
    name: "Log4Shell",
    cve: "CVE-2021-44228",

    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description:
      "Remote code execution in Apache Log4j. A network attacker with no privileges and no user interaction can fully compromise confidentiality, integrity, and availability — and the damage spreads to downstream systems.",
    callouts: [
      { feature: "star-points", label: "8 points: Network attack", anchor: "center" },
      { feature: "star-shape", label: "Sharp: Low complexity", anchor: "left" },
      { feature: "ring-brightness", label: "All bright: Full CIA impact", anchor: "right" },
      { feature: "spikes", label: "Spikes: No user interaction", anchor: "top-right" },
      { feature: "split-band", label: "Split band: Scope Changed", anchor: "bottom-left" },
    ],
  },
  {
    name: "Heartbleed",
    cve: "CVE-2014-0160",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    description:
      "Information disclosure in OpenSSL. Only confidentiality is impacted — the glyph shows a single bright sector while the rest remain dark, demonstrating CIA independence.",
    callouts: [
      { feature: "ring-brightness", label: "One sector lit: Confidentiality only", anchor: "right" },
      { feature: "star-outline", label: "Thin outline: No privileges needed", anchor: "left" },
      { feature: "spikes", label: "Spikes: No user interaction", anchor: "top-right" },
      { feature: "color", label: "Orange-red: High severity", anchor: "bottom" },
    ],
  },
  {
    name: "Spectre",
    cve: "CVE-2017-5715",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "Speculative execution side-channel. Local access, high complexity, low privileges — the blunt star and split band show scope change reaching downstream systems, with only confidentiality impacted.",
    callouts: [
      { feature: "star-points", label: "4 points: Local access", anchor: "center" },
      { feature: "star-shape", label: "Blunt: High complexity", anchor: "inner-left" },
      { feature: "ring-brightness", label: "One sector lit: Confidentiality only", anchor: "right" },
      { feature: "split-band", label: "Split band: Scope Changed", anchor: "bottom-left" },
      { feature: "star-outline", label: "Medium stroke: Low privileges", anchor: "left" },
    ],
  },
  // {
  //   name: "Phishing Link",
  //   cve: null,
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  //   description:
  //     "Generic phishing vector requiring active user interaction. The clean perimeter with no spikes shows the calm state — contrast with Log4Shell's aggressive profile.",
  //   callouts: [
  //     { feature: "smooth-edge", label: "Smooth: User action required", anchor: "top-right" },
  //     { feature: "ring-brightness", label: "Dim sectors: Low impact", anchor: "right" },
  //     { feature: "color", label: "Yellow: Medium severity", anchor: "bottom" },
  //     { feature: "star-points", label: "8 points: Network vector", anchor: "center" },
  //   ],
  // },
  {
    name: "EternalBlue",
    cve: "CVE-2017-0144",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "SMB remote code execution used by WannaCry. Full impact on the vulnerable system but no downstream spread — the ring is solid, not split.",
    callouts: null,
  },
  {
    name: "Dirty COW",
    cve: "CVE-2016-5195",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Linux kernel privilege escalation via copy-on-write race condition. Local access with low privileges — high confidentiality and integrity impact but no availability impact.",
    callouts: null,
  },
  {
    name: "BlueKeep",
    cve: "CVE-2019-0708",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "RDP remote code execution. Network-accessible with no interaction needed. Full vulnerable system impact with low downstream spread visible in the split band.",
    callouts: null,
  },
  // {
  //   name: "Phishing Link",
  //   cve: null,
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  //   description:
  //     "Standard phishing requiring active user participation. The smooth perimeter and dim sectors show a contained, user-dependent threat.",
  //   callouts: null,
  // },
  // {
  //   name: "USB Physical",
  //   cve: null,
  //   vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
  //   description:
  //     "Physical USB attack requiring device access. The 3-point star shows physical vector — despite full impact, physical proximity limits real-world risk.",
  //   callouts: null,
  // },
  {
    name: "Rowhammer",
    cve: "CVE-2015-0565",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description:
      "DRAM bit-flip exploit. High complexity with preconditions — the blunt, segmented glyph shows multiple barriers to exploitation alongside significant downstream impact.",
    callouts: null,
  },
  {
    name: "KRACK",
    cve: "CVE-2017-13077",
    vector: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    description:
      "WPA2 key reinstallation attack. Adjacent network access required (6-point star), high complexity with preconditions — only confidentiality affected.",
    callouts: null,
  },
  {
    name: "Shellshock",
    cve: "CVE-2014-6271",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Bash remote code execution via environment variables. Nearly maximum impact but requires specific preconditions — the segmented ring distinguishes it from Log4Shell.",
    callouts: null,
  },
  {
    name: "POODLE",
    cve: "CVE-2014-3566",
    vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
    description:
      "SSL 3.0 padding oracle. High complexity with preconditions and only low confidentiality impact — the subdued glyph reflects a difficult-to-exploit, limited-impact vulnerability.",
    callouts: null,
  },
  {
    name: "Meltdown",
    cve: "CVE-2017-5754",
    vector: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "CPU memory isolation bypass. Similar profile to Spectre — local, high complexity, preconditions required. The split band shows downstream system impact on confidentiality.",
    callouts: null,
  },
  {
    name: "Sudo Baron Samedit",
    cve: "CVE-2021-3156",
    vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Heap overflow in sudo. Local, low complexity, low privileges needed — full CIA impact on the vulnerable system. A sharp 4-point star with all sectors bright.",
    callouts: null,
  },
  // {
  //   name: "DDoS Amplification",
  //   cve: null,
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H",
  //   description:
  //     "DNS amplification DDoS. Only availability is impacted on both vulnerable and downstream systems — a distinctive glyph with a single bright sector and downstream spread.",
  //   callouts: null,
  // },
  // {
  //   name: "XSS Stored",
  //   cve: null,
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  //   description:
  //     "Stored cross-site scripting. Requires low privileges and passive user interaction (bumps, not spikes). Low confidentiality and integrity impact with no availability effect.",
  //   callouts: null,
  // },
];

// Hero glyphs are those with non-null callouts
export const HERO_VULNERABILITIES = VULNERABILITIES.filter(
  (v) => v.callouts !== null
);
