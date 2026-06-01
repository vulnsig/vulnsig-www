"use client";

import { useState } from "react";
import { ScoreDistribution } from "./ScoreDistribution";
import { VectorDistribution } from "./VectorDistribution";
import { mergeVectorDistribution } from "@/lib/metricMerge";

export interface SearchMetrics {
  scoreDistribution: Record<string, number>;
  vectorDistribution: Record<string, Record<string, number>>;
}

interface Props {
  metrics: SearchMetrics;
  total: number;
  truncated: boolean;
}

export function DistributionPanel({ metrics, total, truncated }: Props) {
  const [open, setOpen] = useState(true);
  const merged = mergeVectorDistribution(metrics.vectorDistribution);

  const scoreTotal = Object.values(metrics.scoreDistribution).reduce(
    (a, b) => a + b,
    0,
  );

  if (scoreTotal === 0 && merged.length === 0) return null;

  return (
    <div className="border border-zinc-800 rounded-md mb-4 bg-zinc-900">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-2 text-left cursor-pointer hover:bg-zinc-800/40 transition-colors"
        aria-expanded={open}
      >
        <span className="text-xs text-zinc-400">
          CVE Characteristcs
          <span className="text-zinc-600 ml-2 normal-case tracking-normal">
            across {total}
            {truncated ? "+" : ""} {total === 1 ? "result" : "results"}
          </span>
        </span>
        <svg
          className={`w-3 h-3 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>
      {open && (
        <div className="px-4 pb-4">
          {scoreTotal > 0 && (
            <section>
              <h4 className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-2">
                Base score
              </h4>
              <ScoreDistribution distribution={metrics.scoreDistribution} />
            </section>
          )}
          {merged.length > 0 && (
            <section>
              <h4 className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-2">
                Vector Metrics
              </h4>

              <VectorDistribution metrics={merged} total={total} />
            </section>
          )}
        </div>
      )}
    </div>
  );
}
