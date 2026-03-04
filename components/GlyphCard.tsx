"use client";

import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";

interface GlyphCardProps {
  name: string;
  nameMono?: boolean;
  cveId?: string;
  subtitle?: string;
  description: string;
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
  vector,
  score,
  onLoadVector,
}: GlyphCardProps) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg px-2 pt-2 pb-4 flex flex-col items-center gap-2 hover:border-zinc-700 transition-colors">
      <div aria-label={`${name} vulnerability glyph, score ${score}`}>
        <VulnSig vector={vector} size={100} score={score} />
      </div>

      <div className="text-center w-full">
        <div className="flex items-center justify-center gap-2 mb-2">
          <h3
            className={`font-semibold text-sm ${nameMono ? "font-mono" : ""}`}
          >
            {name}
          </h3>
          <ScoreBadge score={score} size="sm" />
        </div>
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
        {subtitle && <p className="text-xs text-zinc-600 mb-2">{subtitle}</p>}
        <p className="text-sm text-zinc-400 leading-relaxed mb-2 line-clamp-3">
          {description}
        </p>
        <p className="font-mono text-xs text-zinc-600 mb-4 break-all">
          {vector}
        </p>
        <button
          onClick={onLoadVector}
          className="text-xs font-mono text-zinc-400 hover:text-zinc-100 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          Try in builder
        </button>
      </div>
    </div>
  );
}
