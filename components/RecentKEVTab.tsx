"use client";

import { useState, useMemo } from "react";
import { VirtuosoGrid } from "react-virtuoso";
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
  const { kevData, kevProductMap } = useData();
  const [sort, setSort] = useState<SortMode>("date-desc");

  const latestPublished = kevData.cves[0]?.published ?? "";
  const earliestPublished =
    kevData.cves[kevData.cves.length - 1]?.published ?? "";

  const sorted = useMemo(() => {
    const items = [...kevData.cves];
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
  }, [sort, kevData.cves]);

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
            from {formatDate(earliestPublished)} to{" "}
            {formatDate(latestPublished)}
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

      <VirtuosoGrid
        useWindowScroll
        totalCount={sorted.length}
        listClassName="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
        itemContent={(index) => {
          const kev = sorted[index];
          return (
            <GlyphCard
              name={kev.id}
              nameMono
              cveId={kev.id}
              subtitle={`${formatDate(kev.published)} · CVSS ${kev.cvss.version}`}
              description={kev.description}
              productName={kevProductMap[kev.id]?.product}
              vector={kev.cvss.vectorString}
              score={kev.cvss.baseScore}
              onLoadVector={() =>
                loadVector({
                  name: kev.id,
                  cve: kev.id,
                  vector: kev.cvss.vectorString,
                  description: kev.description,
                })
              }
            />
          );
        }}
      />
    </div>
  );
}
