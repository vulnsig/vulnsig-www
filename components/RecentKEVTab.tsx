"use client";

import { useState, useMemo } from "react";
import { useBuilder } from "./BuilderContext";
import { useData } from "./DataContext";
import { GlyphCard } from "./GlyphCard";

type SortMode = "date-desc" | "date-asc" | "score-desc" | "score-asc";

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function RecentKEVTab() {
  const { loadVector } = useBuilder();
  const { kevData } = useData();
  const [sort, setSort] = useState<SortMode>("date-desc");

  const sorted = useMemo(() => {
    const items = kevData.cves.slice(0, 40);
    switch (sort) {
      case "date-desc":
        return items.sort((a, b) => b.published.localeCompare(a.published));
      case "date-asc":
        return items.sort((a, b) => a.published.localeCompare(b.published));
      case "score-desc":
        return items.sort((a, b) => b.cvss.baseScore - a.cvss.baseScore);
      case "score-asc":
        return items.sort((a, b) => a.cvss.baseScore - b.cvss.baseScore);
    }
  }, [sort, kevData]);

  return (
    <div>
      <div className="flex items-center justify-between mb-4 gap-4">
        <p className="text-sm text-zinc-400">
          {sorted.length} recent{" "}
          <a
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
            rel="noopener noreferrer"
            className="text-zinc-400 hover:text-zinc-200 underline underline-offset-2 decoration-zinc-600 hover:decoration-zinc-400 transition-colors"
          >
            Known Exploited Vulnerabilities
          </a>{" "}
          <span className="text-zinc-600">
            up to {formatDate(kevData.cves[0]?.published ?? "")}
            {" as of "}
            {new Date(kevData.generatedAt).toLocaleString("en-US", {
              year: "numeric",
              month: "short",
              day: "numeric",
              hour: "numeric",
              minute: "2-digit",
            })}
          </span>
        </p>
        <div className="flex items-center gap-2">
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as SortMode)}
            className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono text-zinc-300 cursor-pointer"
          >
            <option value="date-desc">Date (newest first)</option>
            <option value="date-asc">Date (oldest first)</option>
            <option value="score-desc">Score (high → low)</option>
            <option value="score-asc">Score (low → high)</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {sorted.map((cve) => (
          <GlyphCard
            key={cve.id}
            name={cve.id}
            nameMono
            cveId={cve.id}
            subtitle={`${formatDate(cve.published)} · CVSS ${cve.cvss.version}`}
            description={cve.description}
            vector={cve.cvss.vectorString}
            score={cve.cvss.baseScore}
            onLoadVector={() =>
              loadVector({
                name: cve.id,
                cve: cve.id,
                vector: cve.cvss.vectorString,
                description: cve.description,
              })
            }
          />
        ))}
      </div>
    </div>
  );
}
