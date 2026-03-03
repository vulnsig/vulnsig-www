"use client";

import Prism from "prismjs";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-python";
import "prismjs/components/prism-jsx";
import "prismjs/components/prism-tsx";
import "prismjs/components/prism-markup";
import "prismjs/components/prism-markdown";
import { useMemo } from "react";
import { useBuilder } from "./BuilderContext";
import { calculateScore } from "vulnsig";

const LANG_MAP: Record<string, string> = {
  "TypeScript (Core library)": "tsx",
  React: "tsx",
  Python: "python",
  "TypeScript / JavaScript": "bash",
  "HTML embed": "markup",
  Markdown: "markdown",
  curl: "bash",
  bash: "bash",
};

function CodeBlock({ label, code }: { label?: string; code: string }) {
  const html = useMemo(() => {
    const lang = (label && LANG_MAP[label]) || "bash";
    const grammar = Prism.languages[lang];
    if (!grammar) return null;
    return Prism.highlight(code, grammar, lang);
  }, [code, label]);

  return (
    <div className="mb-4">
      {label && <p className="text-xs font-mono text-zinc-500 mb-1">{label}</p>}
      <pre className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 overflow-x-auto">
        {html ? (
          <code
            className="text-sm font-mono"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        ) : (
          <code className="text-sm font-mono text-zinc-300">{code}</code>
        )}
      </pre>
    </div>
  );
}

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

export function PackagesTab() {
  const { vector } = useBuilder();
  const score = calculateScore(vector);
  const encodedVector = encodeURIComponent(vector);

  return (
    <div className="space-y-16">
      {/* TypeScript & React */}
      <div>
        <h3 id="pkg-typescript" className="text-lg font-semibold mb-6">
          TypeScript &amp; React
        </h3>
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Install
            </h4>
            <CodeBlock
              code={`npm install vulnsig           # Core — SVG string output
npm install vulnsig-react     # React component`}
            />
            <div className="flex gap-3 text-sm">
              <ExternalLink href="https://www.npmjs.com/package/vulnsig">
                npm: vulnsig
              </ExternalLink>
              <span className="text-zinc-700">·</span>
              <ExternalLink href="https://www.npmjs.com/package/vulnsig-react">
                npm: vulnsig-react
              </ExternalLink>
              <span className="text-zinc-700">·</span>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-ts">
                GitHub
              </ExternalLink>
            </div>
          </div>
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Usage
            </h4>
            <CodeBlock
              label="TypeScript (Core library)"
              code={`import { renderGlyph } from 'vulnsig';

const svg = renderGlyph({
  vector: '${vector}',
  size: 120,
});
// svg is an SVG string you can embed or save`}
            />
            <CodeBlock
              label="React"
              code={`import { VulnSig } from 'vulnsig-react';

<VulnSig
  vector="${vector}"
  size={120}
  score={${score}}  // optional; auto-calculated if omitted
/>`}
            />
          </div>
        </div>
      </div>

      {/* Python */}
      <div>
        <h3 id="pkg-python" className="text-lg font-semibold mb-6">
          Python
        </h3>
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Install
            </h4>
            <CodeBlock code={`pip install vulnsig`} />
            <div className="flex gap-3 text-sm">
              <ExternalLink href="https://pypi.org/project/vulnsig">
                PyPI: vulnsig
              </ExternalLink>
              <span className="text-zinc-700">·</span>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-py">
                GitHub
              </ExternalLink>
            </div>
          </div>
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Usage
            </h4>
            <CodeBlock
              label="Python"
              code={`from vulnsig import render_glyph

svg = render_glyph(
    vector="${vector}",
    size=120,
)
# svg is an SVG string`}
            />
          </div>
        </div>
      </div>

      {/* REST API */}
      <div>
        <h3 id="pkg-rest-api" className="text-lg font-semibold mb-6">
          REST API
        </h3>
        <p className="text-sm text-zinc-400 mb-4">
          Generate SVG glyphs via HTTP. Same vector, same output — responses are
          cached aggressively.
        </p>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 mb-4">
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
                <td className="py-2 text-zinc-400">
                  Rendered size in pixels (default: 120)
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">score</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">
                  Override auto-calculated score (0-10)
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          label="HTML embed"
          code={`<img src="https://vulnsig.io/api/v1/svg?vector=${encodedVector}" />`}
        />

        <CodeBlock
          label="Markdown"
          code={`![vulnsig](https://vulnsig.io/api/v1/svg?vector=${encodedVector}&size=64)`}
        />

        <CodeBlock
          label="curl"
          code={`curl "https://vulnsig.io/api/v1/svg?vector=${encodedVector}" -o glyph.svg`}
        />

        <div className="mt-4">
          <p className="text-xs font-mono text-zinc-500 mb-2">
            Error response (400)
          </p>
          <pre className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 overflow-x-auto">
            <code className="text-sm font-mono text-zinc-300">{`{ "error": "Invalid CVSS vector", "detail": "..." }`}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}
