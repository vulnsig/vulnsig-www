"use client";

import { calculateScore } from "vulnsig";
import { useBuilder } from "./BuilderContext";
import { GlyphCard } from "./GlyphCard";
import type { Vulnerability } from "@/data/vulnerabilities";

export function GalleryCard({ vuln }: { vuln: Vulnerability }) {
  const { loadVector } = useBuilder();
  const score = calculateScore(vuln.vector);

  return (
    <GlyphCard
      name={vuln.name}
      cveId={vuln.cve ?? undefined}
      description={vuln.description}
      vector={vuln.vector}
      score={score}
      onLoadVector={() => loadVector(vuln)}
    />
  );
}
