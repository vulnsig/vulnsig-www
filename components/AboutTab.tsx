"use client";

function ExternalLink({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-zinc-300 hover:text-zinc-100 underline underline-offset-2 decoration-zinc-600 hover:decoration-zinc-400 transition-colors"
    >
      {children}
    </a>
  );
}

export function AboutTab() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
      {/* About VulnSig */}
      <div>
        <h3 className="text-lg font-semibold mb-4">About VulnSig</h3>
        <div className="space-y-4 text-sm text-zinc-400 leading-relaxed mb-6">
          <p>
            VulnSig encodes CVSS metrics into a compact visual glyph. Each
            shape, characteristic, and color maps to a specific metric: attack
            vector, complexity, privileges; impact on confidentiality,
            integrity, and availability; scope change, and more.
          </p>
          <p>
            While the the CVSS vector provides rich information, many
            applications only report the CVSS score. The goal of VulnSig is to
            make vulnerability characteristics beyond just severity immediately
            legible. Two vulnerabilities with the same numeric score can look
            very different as glyphs.
          </p>
          <p>
            VulnSig supports CVSS 4.0, 3.1, and 3.0. It is freely available as a
            TypeScript library, a React component, a Python library, and a REST
            API.
          </p>
          <p>
            VulnSig was created by <ExternalLink href="https://www.flexatone.net">Christopher Ariza</ExternalLink>{" "} for application in the{" "}
            <ExternalLink href="https://fetter.io">Fetter IO</ExternalLink>{" "}
            supply-chain monitoring application.
          </p>
        </div>
        <div className="space-y-2 text-sm">
          <p className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-4">
            Source & packages
          </p>
          <ul className="space-y-1.5">
            <li>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-ts">
                github.com/vulnsig/vulnsig-ts
              </ExternalLink>
              <span className="text-zinc-600 ml-2"> TypeScript core</span>
            </li>
            <li>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-react">
                github.com/vulnsig/vulnsig-react
              </ExternalLink>
              <span className="text-zinc-600 ml-2"> React component</span>
            </li>
            <li>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-py">
                github.com/vulnsig/vulnsig-py
              </ExternalLink>
              <span className="text-zinc-600 ml-2"> Python library</span>
            </li>
            <li>
              <ExternalLink href="https://www.npmjs.com/package/vulnsig">
                npm: vulnsig
              </ExternalLink>
              <span className="text-zinc-600 mx-2">·</span>
              <ExternalLink href="https://www.npmjs.com/package/vulnsig-react">
                npm: vulnsig-react
              </ExternalLink>
              <span className="text-zinc-600 mx-2">·</span>
              <ExternalLink href="https://pypi.org/project/vulnsig">
                PyPI: vulnsig
              </ExternalLink>
            </li>
          </ul>
        </div>
      </div>

      {/* About CVSS */}
      <div>
        <h3 className="text-lg font-semibold mb-4">About CVSS</h3>
        <div className="space-y-4 text-sm text-zinc-400 leading-relaxed mb-6">
          <p>
            The Common Vulnerability Scoring System (CVSS) is an open standard
            for rating the severity of security vulnerabilities. It is
            maintained by{" "}
            <ExternalLink href="https://www.first.org">FIRST</ExternalLink>{" "}
            (Forum of Incident Response and Security Teams) and widely adopted
            by vendors, researchers, and vulnerability databases worldwide.
          </p>
          <p>
            A CVSS vector string encodes a set of metrics defining how a
            vulnerability is accessed, what conditions are required, what
            privileges are needed, and what impact it has on confidentiality,
            integrity, and availability. These metrics are combined into a base
            score from 0 to 10.
          </p>
        </div>
        <div className="space-y-2 text-sm">
          <p className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-4">
            More information
          </p>
          <ul className="space-y-1.5">
            <li>
              <ExternalLink href="https://www.first.org/cvss/">
                first.org/cvss
              </ExternalLink>
              <span className="text-zinc-600 ml-2">
                CVSS specification and calculator (FIRST)
              </span>
            </li>
            <li>
              <ExternalLink href="https://www.first.org/cvss/v4-0/">
                first.org/cvss/v4-0
              </ExternalLink>
              <span className="text-zinc-600 ml-2">
                {" "}
                CVSS 4.0 specification
              </span>
            </li>
            <li>
              <ExternalLink href="https://nvd.nist.gov/vuln-metrics/cvss">
                nvd.nist.gov/vuln-metrics/cvss
              </ExternalLink>
              <span className="text-zinc-600 ml-2">
                NIST NVD CVSS documentation
              </span>
            </li>
            <li>
              <ExternalLink href="https://www.cve.org">cve.org</ExternalLink>
              <span className="text-zinc-600 ml-2">
                CVE Program (vulnerability identifiers)
              </span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
