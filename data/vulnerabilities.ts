export interface Vulnerability {
  name: string;
  cve: string | null;
  vector: string;
  description: string;
}

export const VULNERABILITIES: Vulnerability[] = [
  {
    name: "Log4Shell",
    cve: "CVE-2021-44228",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description:
      "Remote code execution in Apache Log4j. A network attacker with no privileges and no user interaction can fully compromise confidentiality, integrity, and availability — and the damage spreads to downstream systems.",
  },
  {
    name: "Heartbleed",
    cve: "CVE-2014-0160",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    description:
      "Information disclosure in OpenSSL. Only confidentiality is impacted — the glyph shows a single bright sector while the rest remain dark, demonstrating CIA independence.",
  },
  {
    name: "Spectre",
    cve: "CVE-2017-5715",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "Speculative execution side-channel. Local access, high complexity, low privileges — the blunt star and split band show scope change reaching downstream systems, with only confidentiality impacted.",
  },
  {
    name: "EternalBlue",
    cve: "CVE-2017-0144",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "SMB remote code execution used by WannaCry. Full impact on the vulnerable system but no downstream spread — the ring is solid, not split.",
  },
  {
    name: "Dirty COW",
    cve: "CVE-2016-5195",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Linux kernel privilege escalation via copy-on-write race condition. Local access with low privileges — high confidentiality and integrity impact but no availability impact.",
  },
  {
    name: "BlueKeep",
    cve: "CVE-2019-0708",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "RDP remote code execution. Network-accessible with no interaction needed. Full vulnerable system impact with low downstream spread visible in the split band.",
  },
  {
    name: "Rowhammer",
    cve: "CVE-2015-0565",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description:
      "DRAM bit-flip exploit. High complexity with preconditions — the blunt, segmented glyph shows multiple barriers to exploitation alongside significant downstream impact.",
  },
  {
    name: "KRACK",
    cve: "CVE-2017-13077",
    vector: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    description:
      "WPA2 key reinstallation attack. Adjacent network access required (6-point star), high complexity with preconditions — only confidentiality affected.",
  },
  {
    name: "Shellshock",
    cve: "CVE-2014-6271",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Bash remote code execution via environment variables. Nearly maximum impact but requires specific preconditions — the segmented ring distinguishes it from Log4Shell.",
  },
  {
    name: "POODLE",
    cve: "CVE-2014-3566",
    vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N",
    description:
      "SSL 3.0 padding oracle. High complexity with preconditions and only low confidentiality impact — the subdued glyph reflects a difficult-to-exploit, limited-impact vulnerability.",
  },
  {
    name: "Meltdown",
    cve: "CVE-2017-5754",
    vector: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "CPU memory isolation bypass. Similar profile to Spectre — local, high complexity, preconditions required. The split band shows downstream system impact on confidentiality.",
  },
  {
    name: "Sudo Baron Samedit",
    cve: "CVE-2021-3156",
    vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Heap overflow in sudo. Local, low complexity, low privileges needed — full CIA impact on the vulnerable system. A sharp 4-point star with all sectors bright.",
  },
  {
    name: "Next.js Middleware Bypass Vulnerability",
    cve: "CVE-2025-29927",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    description:
      "Next.js uses an internal header x-middleware-subrequest to prevent recursive requests from triggering infinite loops. The security vulnerability shows it's possible to skip running Middleware, which could allow requests to bypass critical checks—such as authorization cookie validation—before reaching routes.",
  },
  {
    name: "regreSSHion",
    cve: "CVE-2024-6387",
    vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.",
  },
  {
    name: "aiohttp directory traversal",
    cve: "CVE-2024-23334",
    vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    description:
      "Improperly configuring static resource resolution in aiohttp when used as a web server can result in the unauthorized reading of arbitrary files on the system.",
  },
  {
    name: "Microsoft Office SharePoint XSS Vulnerability",
    cve: "CVE-2020-0926",
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
    description:
      "A cross-site-scripting (XSS) vulnerability exists when Microsoft SharePoint Server does not properly sanitize a specially crafted web request to an affected SharePoint server.",
  },
];

// note: some 4.0 examples are from here:
// https://www.first.org/cvss/examples
