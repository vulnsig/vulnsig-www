"use client";

function CodeBlock({ label, code }: { label?: string; code: string }) {
  return (
    <div className="mb-4">
      {label && (
        <p className="text-xs font-mono text-zinc-500 mb-1">{label}</p>
      )}
      <pre className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 overflow-x-auto">
        <code className="text-sm font-mono text-zinc-300">{code}</code>
      </pre>
    </div>
  );
}

function ExternalLink({ href, children }: { href: string; children: React.ReactNode }) {
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

export function PackagesTab() {
  return (
    <div className="space-y-12">
      {/* Install */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Install</h3>
        <CodeBlock
          label="TypeScript / JavaScript"
          code={`npm install vulnsig           # Core — SVG string output
npm install vulnsig-react     # React component`}
        />
        <CodeBlock
          label="Python"
          code={`pip install vulnsig            # SVG string output`}
        />
      </div>

      {/* Usage examples */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Usage</h3>

        <CodeBlock
          label="TypeScript — Core library"
          code={`import { renderGlyph } from 'vulnsig';

const svg = renderGlyph({
  vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
  size: 120,
});
// svg is an SVG string you can embed or save`}
        />

        <CodeBlock
          label="React"
          code={`import { VulnSig } from 'vulnsig-react';

<VulnSig
  vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
  size={120}
  score={10.0}  // optional — auto-calculated if omitted
/>`}
        />

        <CodeBlock
          label="Python"
          code={`from vulnsig import render_glyph

svg = render_glyph(
    vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    size=120,
)
# svg is an SVG string`}
        />
      </div>

      {/* Links */}
      <div>
        <h3 className="text-lg font-semibold mb-4">Links</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <div className="space-y-2">
            <p className="text-xs font-mono text-zinc-500 uppercase tracking-wider">GitHub</p>
            <ul className="space-y-1">
              <li><ExternalLink href="https://github.com/vulnsig/vulnsig-ts">vulnsig/vulnsig-ts</ExternalLink></li>
              <li><ExternalLink href="https://github.com/vulnsig/vulnsig-react">vulnsig/vulnsig-react</ExternalLink></li>
              <li><ExternalLink href="https://github.com/vulnsig/vulnsig-py">vulnsig/vulnsig-py</ExternalLink></li>
            </ul>
          </div>
          <div className="space-y-2">
            <p className="text-xs font-mono text-zinc-500 uppercase tracking-wider">Package Registries</p>
            <ul className="space-y-1">
              <li><ExternalLink href="https://www.npmjs.com/package/vulnsig">npm: vulnsig</ExternalLink></li>
              <li><ExternalLink href="https://www.npmjs.com/package/vulnsig-react">npm: vulnsig-react</ExternalLink></li>
              <li><ExternalLink href="https://pypi.org/project/vulnsig">PyPI: vulnsig</ExternalLink></li>
            </ul>
          </div>
        </div>
      </div>

      {/* REST API */}
      <div>
        <h3 className="text-lg font-semibold mb-4">REST API</h3>
        <p className="text-sm text-zinc-400 mb-4">
          Generate SVG glyphs via HTTP. Same vector, same output — responses are cached aggressively.
        </p>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 mb-4">
          <p className="font-mono text-sm text-zinc-300">
            <span className="text-emerald-400">GET</span>{" "}
            https://vulnsig.io/api/v1/svg
          </p>
        </div>

        <div className="overflow-x-auto mb-6">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 border-b border-zinc-800">
                <th className="pb-2 pr-4 font-mono font-normal">Parameter</th>
                <th className="pb-2 pr-4 font-mono font-normal">Type</th>
                <th className="pb-2 pr-4 font-mono font-normal">Required</th>
                <th className="pb-2 font-mono font-normal">Description</th>
              </tr>
            </thead>
            <tbody className="text-zinc-300">
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4 font-mono text-xs">vector</td>
                <td className="py-2 pr-4 text-zinc-400">string</td>
                <td className="py-2 pr-4 text-zinc-400">yes</td>
                <td className="py-2 text-zinc-400">CVSS 4.0 vector string</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4 font-mono text-xs">size</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">Rendered size in pixels (default: 120)</td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">score</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">Override auto-calculated score (0-10)</td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          label="HTML embed"
          code={`<img src="https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" />`}
        />

        <CodeBlock
          label="Markdown"
          code={`![Log4Shell](https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H&size=64)`}
        />

        <CodeBlock
          label="curl"
          code={`curl "https://vulnsig.io/api/v1/svg?vector=CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" -o glyph.svg`}
        />

        <div className="mt-4">
          <p className="text-xs font-mono text-zinc-500 mb-2">Error response (400)</p>
          <pre className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 overflow-x-auto">
            <code className="text-sm font-mono text-zinc-300">{`{ "error": "Invalid CVSS vector", "detail": "..." }`}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}
