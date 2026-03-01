"use client";

import { useState, useMemo } from "react";
import { VULNERABILITIES } from "@/data/vulnerabilities";
import { GalleryCard } from "./GalleryCard";
import { calculateScore } from "vulnsig";

type SortMode = "score-desc" | "score-asc" | "name";

export function GalleryTab() {
  const [sort, setSort] = useState<SortMode>("score-desc");

  // Deduplicate by name (different CVEs can share the same vector)
  const unique = useMemo(() => {
    const seen = new Set<string>();
    return VULNERABILITIES.filter((v) => {
      if (seen.has(v.name)) return false;
      seen.add(v.name);
      return true;
    });
  }, []);

  const sorted = useMemo(() => {
    const items = [...unique];
    switch (sort) {
      case "score-desc":
        return items.sort(
          (a, b) => calculateScore(b.vector) - calculateScore(a.vector),
        );
      case "score-asc":
        return items.sort(
          (a, b) => calculateScore(a.vector) - calculateScore(b.vector),
        );
      case "name":
        return items.sort((a, b) => a.name.localeCompare(b.name));
    }
  }, [unique, sort]);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-zinc-400">{sorted.length} vulnerabilities</p>
        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-500">Sort:</span>
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as SortMode)}
            className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono text-zinc-300 cursor-pointer"
          >
            <option value="score-desc">Score (high → low)</option>
            <option value="score-asc">Score (low → high)</option>
            <option value="name">Name</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {sorted.map((vuln) => (
          <GalleryCard key={vuln.cve ?? vuln.name} vuln={vuln} />
        ))}
      </div>
    </div>
  );
}
