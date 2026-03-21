"use client";

import { VulnSig } from "vulnsig-react";
import { calculateScore } from "vulnsig";
import { useBuilder } from "./BuilderContext";

interface HeroSectionCveProps {
  cveId: string;
  vector: string;
  score: number | undefined;
  description: string | undefined;
}

export function HeroSectionCve({
  cveId,
  vector: vectorProp,
  score: scoreProp,
  description,
}: HeroSectionCveProps) {
  const { heroRef, vector } = useBuilder();

  const activeVector = vector || vectorProp;
  const score = scoreProp ?? calculateScore(activeVector);

  return (
    <section className="w-full pt-16 pb-4 px-4">
      <div className="max-w-6xl mx-auto">
        <div ref={heroRef} className="flex justify-center">
          <div className="flex items-center w-full px-0">
            {/* Left half: glyph, right-justified */}
            <div className="flex-1 flex justify-end">
              <div className="flex-none">
                <VulnSig vector={activeVector} size={200} score={score} />
              </div>
            </div>

            {/* Right half: CVE info, left-justified */}
            <div className="flex-1">
              <div className="min-w-0 pl-0 pr-4">
                <p className="font-semibold text-sm text-zinc-200">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-zinc-300 transition-colors"
                  >
                    {cveId}
                  </a>
                </p>
                {description && (
                  <p className="text-sm text-zinc-400 mt-4 leading-relaxed break-words">
                    {description}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
