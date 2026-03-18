"use client";

import type { ReactNode } from "react";
import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";
import { useBuilder } from "./BuilderContext";
import { ShareButton } from "./ShareButton";

/** Highlight the first occurrence of `term` in `text`, case-insensitive. */
function highlightFirst(text: string, term: string): ReactNode {
  const idx = text.toLowerCase().indexOf(term.toLowerCase());
  if (idx === -1) return text;
  const before = text.slice(0, idx);
  const match = text.slice(idx, idx + term.length);
  const after = text.slice(idx + term.length);
  return (
    <>
      {before}
      <span className="text-zinc-200 font-medium">{match}</span>
      {after}
    </>
  );
}

interface GlyphCardProps {
  name: string;
  nameMono?: boolean;
  cveId?: string;
  subtitle?: string;
  description: string;
  /** When set, the first occurrence of this product name in the description is highlighted. */
  productName?: string;
  vector: string;
  score: number;
  onLoadVector: () => void;
}

export function GlyphCard({
  name,
  nameMono,
  cveId,
  subtitle,
  description,
  productName,
  vector,
  score,
  onLoadVector,
}: GlyphCardProps) {
  const { loadVector: loadVectorCtx, setExpanded } = useBuilder();

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg h-90 px-4 pt-2 pb-4 flex flex-col items-center hover:border-zinc-700 transition-colors">
      <div
        className="relative"
        aria-label={`${name} vulnerability glyph, score ${score}`}
      >
        <VulnSig vector={vector} size={100} score={score} />
        <div className="absolute top-1/2 -translate-y-1/2 left-full ml-2 flex flex-row items-center gap-2">
          <button
            onClick={onLoadVector}
            title="Try in builder"
            className="text-zinc-600 hover:text-zinc-300 transition-colors cursor-pointer"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* Top-left */}
              <polyline points="4,10 4,4 10,4" />
              <line x1="4" y1="4" x2="11" y2="11" />
              {/* Top-right */}
              <polyline points="14,4 20,4 20,10" />
              <line x1="20" y1="4" x2="13" y2="11" />
              {/* Bottom-right */}
              <polyline points="20,14 20,20 14,20" />
              <line x1="20" y1="20" x2="13" y2="13" />
              {/* Bottom-left */}
              <polyline points="10,20 4,20 4,14" />
              <line x1="4" y1="20" x2="11" y2="13" />
            </svg>
          </button>
          {cveId && (
            <ShareButton
              cveId={cveId}
              vector={vector}
              score={score}
              description={description}
              productName={productName}
            />
          )}
        </div>
      </div>

      <div className="text-center w-full flex-1 min-h-0 flex flex-col">
        <div className="flex items-center justify-center gap-2 mb-2">
          <h3
            className={`font-semibold text-sm ${nameMono ? "font-mono" : ""}`}
          >
            {name}
          </h3>
          <ScoreBadge score={score} size="sm" />
        </div>
        <div className="overflow-y-auto flex-1 min-h-0">
          {cveId && (
            <a
              href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="block font-mono text-xs text-zinc-500 hover:text-zinc-300 transition-colors mb-2"
            >
              {cveId}
            </a>
          )}
          {subtitle && <p className="text-xs text-zinc-500 mb-2">{subtitle}</p>}
          <p className="text-sm text-zinc-400 mb-2 break-words">
            {productName
              ? highlightFirst(description, productName)
              : description}
          </p>
          <button
            onClick={() => {
              loadVectorCtx({
                name: name,
                cve: cveId ?? null,
                vector,
                description,
              });
              setExpanded(false);
            }}
            title="Set as active vector"
            className="font-mono text-xs text-zinc-500 hover:text-zinc-300 break-all text-center cursor-pointer transition-colors"
          >
            {vector}
          </button>
        </div>
      </div>
    </div>
  );
}
