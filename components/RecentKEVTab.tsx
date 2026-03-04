"use client";

import { useState, useMemo } from "react";
import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";
import { useBuilder } from "./BuilderContext";
import { useData } from "./DataContext";

type SortMode = "date-desc" | "date-asc" | "score-desc" | "score-asc";

function displayVector(vectorString: string): string {
  const cut = vectorString.indexOf("/E:");
  return cut !== -1 ? vectorString.slice(0, cut) : vectorString;
}

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
        {sorted.map((cve) => {
          const vector = cve.cvss.vectorString;
          const score = cve.cvss.baseScore;

          return (
            <div
              key={cve.id}
              className="bg-zinc-900 border border-zinc-800 rounded-lg px-2 pt-2 pb-4 flex flex-col items-center gap-2 hover:border-zinc-700 transition-colors"
            >
              <div aria-label={`${cve.id} glyph, score ${score}`}>
                <VulnSig vector={vector} size={100} score={score} />
              </div>

              <div className="text-center w-full">
                <div className="flex items-center justify-center gap-2 mb-2">
                  <h3 className="font-semibold text-sm font-mono">{cve.id}</h3>
                  <ScoreBadge score={score} size="sm" />
                </div>
                <p className="font-mono text-xs text-zinc-600 mb-2">
                  {formatDate(cve.published)} · CVSS {cve.cvss.version}
                </p>
                <p className="text-sm text-zinc-400 leading-relaxed mb-2 line-clamp-3">
                  {cve.description}
                </p>
                <p className="font-mono text-xs text-zinc-600 mb-4 break-all">
                  {displayVector(vector)}
                </p>
                <button
                  onClick={() =>
                    loadVector({
                      name: cve.id,
                      cve: cve.id,
                      vector,
                      description: cve.description,
                    })
                  }
                  className="text-xs font-mono text-zinc-400 hover:text-zinc-100 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
                >
                  Try in builder
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
