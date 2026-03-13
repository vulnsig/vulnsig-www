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
      "Remote code execution in Apache Log4j. A network attacker with no privileges and no user interaction can fully compromise confidentiality, integrity, and availability, and the damage spreads to downstream systems.",
  },
  {
    name: "Heartbleed",
    cve: "CVE-2014-0160",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    description:
      "Information disclosure in OpenSSL. Only confidentiality is impacted.",
  },
  {
    name: "Spectre",
    cve: "CVE-2017-5715",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "Speculative execution side-channel. Local access, high complexity, low privileges; only confidentiality impacted.",
  },
  {
    name: "EternalBlue",
    cve: "CVE-2017-0144",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "A Windows SMB vulnerability exploited to propagate the WannaCry ransomware globally. Full impact on the vulnerable system but no downstream spread.",
  },
  {
    name: "Dirty COW",
    cve: "CVE-2016-5195",
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Linux kernel privilege escalation via copy-on-write race condition. Local access with low privileges: high confidentiality and integrity impact but no availability impact.",
  },
  {
    name: "BlueKeep",
    cve: "CVE-2019-0708",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "RDP remote code execution. Network-accessible with no interaction needed. Full vulnerable system impact with low downstream spread.",
  },
  {
    name: "Rowhammer",
    cve: "CVE-2015-0565",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description: "DRAM bit-flip exploit. High complexity with preconditions.",
  },
  {
    name: "KRACK",
    cve: "CVE-2017-13077",
    vector: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    description:
      "WPA2 key reinstallation attack. Adjacent network access required, high complexity with preconditions; confidentiality and integrity affected.",
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
      "SSL 3.0 padding oracle. High complexity with preconditions and only low confidentiality impact; a difficult-to-exploit, limited-impact vulnerability.",
  },
  {
    name: "Meltdown",
    cve: "CVE-2017-5754",
    vector: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
    description:
      "CPU memory isolation bypass. Similar profile to Spectre — local, high complexity, preconditions required; downstream system impact on confidentiality.",
  },
  {
    name: "Sudo Baron Samedit",
    cve: "CVE-2021-3156",
    vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "Heap overflow in sudo. Local, low complexity, low privileges needed; full CIA impact on the vulnerable system.",
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
  // {
  //   name: "aiohttp directory traversal",
  //   cve: "CVE-2024-23334",
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
  //   description:
  //     "Improperly configuring static resource resolution in aiohttp when used as a web server can result in the unauthorized reading of arbitrary files on the system.",
  // },
  // {
  //   name: "Microsoft Office SharePoint XSS Vulnerability",
  //   cve: "CVE-2020-0926",
  //   vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N",
  //   description:
  //     "A cross-site-scripting (XSS) vulnerability exists when Microsoft SharePoint Server does not properly sanitize a specially crafted web request to an affected SharePoint server.",
  // },
  {
    name: "PaperCut",
    cve: "CVE-2023-27350",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "PaperCut servers vulnerable to CVE-2023-27350 implement improper access controls in the SetupCompleted Java class, allowing malicious actors to bypass user authentication and access the server as an administrator.",
  },
  {
    name: "ProxyShell",
    cve: "CVE-2021-34473",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "A chain of Microsoft Exchange vulnerabilities widely exploited for RCE.",
  },
  {
    name: "Microsoft Office Memory Corruption",
    cve: "CVE-2017-11882",
    vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    description:
      "A long-standing vulnerability in the Equation Editor, frequently used in phishing campaigns.",
  },
  {
    name: "NFS mount daemon",
    cve: "CVE-1999-0211",
    vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    description:
      "Extra long export lists over 256 characters in some mount daemons allows NFS directories to be mounted by anyone.",
  },
  {
    name: "Folina",
    cve: "CVE-2022-30190",
    vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    description:
      "A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights.",
  },
  {
    name: "PetitPotam",
    cve: "CVE-2021-36942",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    description:
      "Windows LSA Spoofing Vulnerability. Allows unauthenticated attackers to take over Windows Domain Controllers and compromise an entire Active Directory domain.",
  },
  {
    name: "PrintNightmare",
    cve: "CVE-2021-34527",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description:
      "A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.",
  },
  {
    name: "CitrixBleed",
    cve: "CVE-2023-4966",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    description:
      "Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA  virtual server.",
  },
  {
    name: "ACE on affected Tesla vehicles",
    cve: "CVE-2022-3093",
    vector: "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description:
      "This vulnerability allows physical attackers to execute arbitrary code on affected Tesla vehicles. Authentication is not required to exploit this vulnerability. The specific flaw exists within the ice_updater update mechanism. The issue results from the lack of proper validation of user-supplied firmware. An attacker can leverage this vulnerability to execute code in the context of root.",
  },
  {
    name: "TP-Link Tapo H200 V1 Exposed Credentials",
    cve: "CVE-2025-3442",
    vector: "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
    description:
      "This vulnerability exists in TP-Link Tapo H200 V1 IoT Smart Hub due to storage of Wi-Fi credentials in plain text within the device firmware. An attacker with physical access could exploit this by extracting the firmware and analyzing the binary data to obtain the Wi-Fi credentials stored on the vulnerable device.",
  },
  {
    name: "Wattsense Bridge Device Compromise",
    cve: "CVE-2025-26408",
    vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    description:
      "The JTAG interface of Wattsense Bridge devices can be accessed with physical access to the PCB. After connecting to the interface, full access to the device is possible. This enables an attacker to extract information, modify and debug the device's firmware. All known versions are affected.",
  },
  {
    name: "Exposed Credentials in GE HealthCare EchoPAC",
    cve: "CVE-2024-27109",
    vector: "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    description:
      "Insufficiently protected credentials in GE HealthCare EchoPAC products.",
  },
  {
    name: "Gallium",
    cve: "CVE-2023-38606",
    vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    description:
      "An issue in the kernel that permits a malicious app to modify sensitive kernel state.",
  },
  {
    name: "Photon",
    cve: "CVE-2023-32434",
    vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    description:
      "An integer overflow vulnerability in the kernel that could be exploited by a malicious app to execute arbitrary code with kernel privileges.",
  },
];

// note: some 4.0 examples are from here:
// https://www.first.org/cvss/examples
// historical examples here:
// https://www.tenable.com/blog/from-bugs-to-breaches-25-significant-cves-as-mitre-cve-turns-25
