"use client";

import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";
import { useBuilder } from "./BuilderContext";
import { calculateScore } from "vulnsig";
import type { Vulnerability } from "@/data/vulnerabilities";

export function GalleryCard({ vuln }: { vuln: Vulnerability }) {
  const { loadVector } = useBuilder();
  const score = calculateScore(vuln.vector);

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5 flex flex-col items-center gap-3 hover:border-zinc-700 transition-colors">
      <div aria-label={`${vuln.name} vulnerability glyph, score ${score}`}>
        <VulnSig vector={vuln.vector} size={100} score={score} />
      </div>

      <div className="text-center w-full">
        <div className="flex items-center justify-center gap-2 mb-1">
          <h3 className="font-semibold text-sm">{vuln.name}</h3>
          <ScoreBadge score={score} size="sm" />
        </div>
        {vuln.cve && (
          <p className="font-mono text-xs text-zinc-500 mb-2">{vuln.cve}</p>
        )}
        <p className="text-xs text-zinc-400 leading-relaxed mb-3 line-clamp-3">
          {vuln.description}
        </p>
        <p className="font-mono text-[10px] text-zinc-600 mb-3 break-all">
          {vuln.vector}
        </p>
        <button
          onClick={() => loadVector(vuln.vector)}
          className="text-xs font-mono text-zinc-400 hover:text-zinc-100 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          Try in builder
        </button>
      </div>
    </div>
  );
}
