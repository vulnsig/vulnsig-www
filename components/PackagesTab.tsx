"use client";

import Prism from "prismjs";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-python";
import "prismjs/components/prism-jsx";
import "prismjs/components/prism-tsx";
import "prismjs/components/prism-markup";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-rust";
import { useMemo, useState, useCallback } from "react";
import { useBuilder } from "./BuilderContext";
import { calculateScore } from "vulnsig";

const LANG_MAP: Record<string, string> = {
  "TypeScript (Core library)": "tsx",
  React: "tsx",
  Python: "python",
  Rust: "rust",
  "TypeScript / JavaScript": "bash",
  "HTML embed": "markup",
  Markdown: "markdown",
  curl: "bash",
  bash: "bash",
};

function CodeBlock({ label, code }: { label?: string; code: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [code]);

  const html = useMemo(() => {
    const lang = (label && LANG_MAP[label]) || "bash";
    const grammar = Prism.languages[lang];
    if (!grammar) return null;
    return Prism.highlight(code, grammar, lang);
  }, [code, label]);

  return (
    <div className="mb-4">
      {label && <p className="text-xs font-mono text-zinc-500 mb-1">{label}</p>}
      <pre
        onClick={handleCopy}
        className="bg-zinc-900 border border-zinc-800 rounded-lg pl-4 pr-8 py-2 cursor-pointer hover:border-zinc-700 transition-colors relative group whitespace-pre-wrap break-all"
      >
        <span className="absolute top-2 right-2 text-zinc-600 group-hover:text-zinc-400 transition-colors">
          {copied ? (
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="3.5 8.5 6.5 11.5 12.5 4.5" />
            </svg>
          ) : (
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" />
              <path d="M10.5 5.5V3a1.5 1.5 0 0 0-1.5-1.5H3A1.5 1.5 0 0 0 1.5 3v6A1.5 1.5 0 0 0 3 10.5h2.5" />
            </svg>
          )}
        </span>
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
      {/* TypeScript */}
      <div>
        <h3 id="pkg-typescript" className="text-lg font-semibold mb-6">
          TypeScript
        </h3>
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Install
            </h4>
            <CodeBlock code={`npm install vulnsig`} />
            <div className="flex gap-3 text-sm">
              <ExternalLink href="https://www.npmjs.com/package/vulnsig">
                npm: vulnsig
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
          </div>
        </div>
      </div>

      {/* React */}
      <div>
        <h3 id="pkg-react" className="text-lg font-semibold mb-6">
          React
        </h3>
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Install
            </h4>
            <CodeBlock code={`npm install vulnsig-react`} />
            <div className="flex gap-3 text-sm">
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

      {/* Rust */}
      <div>
        <h3 id="pkg-rust" className="text-lg font-semibold mb-6">
          Rust
        </h3>
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Install
            </h4>
            <CodeBlock code={`cargo add vulnsig`} />
            <div className="flex gap-3 text-sm">
              <ExternalLink href="https://crates.io/crates/vulnsig">
                crates.io: vulnsig
              </ExternalLink>
              <span className="text-zinc-700">·</span>
              <ExternalLink href="https://github.com/vulnsig/vulnsig-rs">
                GitHub
              </ExternalLink>
            </div>
          </div>
          <div>
            <h4 className="text-sm font-mono text-zinc-500 uppercase tracking-wider mb-3">
              Usage
            </h4>
            <CodeBlock
              label="Rust"
              code={`use vulnsig::render_glyph;

let svg = render_glyph(
    "${vector}",
    None,      // score: auto-calculated if None
    Some(120), // size in pixels
);
// svg is an SVG string`}
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
          Generate SVG glyphs via HTTP. Responses are cached aggressively.
        </p>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 mb-4">
          <p className="font-mono text-sm text-zinc-300">
            <span className="text-emerald-400">GET</span>{" "}
            https://vulnsig.io/api/svg
          </p>
        </div>

        <div className="overflow-x-auto mb-6 bg-zinc-900 border border-zinc-800 rounded-lg p-4">
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
                <td className="py-2 text-zinc-400">
                  CVSS 4.0 or 3.x vector string
                </td>
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
          code={`<img src="https://vulnsig.io/api/svg?vector=${encodedVector}" />`}
        />

        <CodeBlock
          label="Markdown"
          code={`![vulnsig](https://vulnsig.io/api/svg?vector=${encodedVector}&size=64)`}
        />

        <CodeBlock
          label="curl"
          code={`curl "https://vulnsig.io/api/svg?vector=${encodedVector}" -o glyph.svg`}
        />

        <div className="mt-4">
          <p className="text-xs font-mono text-zinc-500 mb-2">
            Error response (400)
          </p>
          <pre className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 overflow-x-auto">
            <code className="text-sm font-mono text-zinc-300">{`{ "error": "Invalid CVSS vector", "detail": "..." }`}</code>
          </pre>
        </div>

        <hr className="border-zinc-800 my-10" />

        <p className="text-sm text-zinc-400 mb-4">
          Generate PNG glyphs with transparent backgrounds via HTTP.
        </p>

        <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-2 mb-4">
          <p className="font-mono text-sm text-zinc-300">
            <span className="text-emerald-400">GET</span>{" "}
            https://vulnsig.io/api/png
          </p>
        </div>

        <div className="overflow-x-auto mb-6 bg-zinc-900 border border-zinc-800 rounded-lg p-4">
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
                <td className="py-2 text-zinc-400">
                  CVSS 4.0 or 3.x vector string
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4 font-mono text-xs">size</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">
                  Rendered size in pixels (default: 120)
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4 font-mono text-xs">score</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">
                  Override auto-calculated score (0-10)
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4 font-mono text-xs">density</td>
                <td className="py-2 pr-4 text-zinc-400">number</td>
                <td className="py-2 pr-4 text-zinc-400">no</td>
                <td className="py-2 text-zinc-400">
                  Render density in DPI (default: 72, max: 600)
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <CodeBlock
          label="HTML embed"
          code={`<img src="https://vulnsig.io/api/png?vector=${encodedVector}" />`}
        />

        <CodeBlock
          label="Markdown"
          code={`![vulnsig](https://vulnsig.io/api/png?vector=${encodedVector}&size=64)`}
        />

        <CodeBlock
          label="curl"
          code={`curl "https://vulnsig.io/api/png?vector=${encodedVector}" -o glyph.png`}
        />
      </div>
    </div>
  );
}
