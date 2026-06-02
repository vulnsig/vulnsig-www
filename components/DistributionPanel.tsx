"use client";

import { useState } from "react";
import { ScoreDistribution } from "./ScoreDistribution";
import { VectorDistribution } from "./VectorDistribution";
import { MetricsEmbedDialog } from "./MetricsEmbedDialog";
import { mergeVectorDistribution } from "@/lib/metricMerge";

export interface SearchMetrics {
  scoreDistribution: Record<string, number>;
  vectorDistribution: Record<string, Record<string, number>>;
}

interface Props {
  metrics: SearchMetrics;
  total: number;
  truncated: boolean;
  query: string;
}

export function DistributionPanel({ metrics, total, truncated, query }: Props) {
  const [open, setOpen] = useState(true);
  const [embedOpen, setEmbedOpen] = useState(false);
  const merged = mergeVectorDistribution(metrics.vectorDistribution);

  const scoreTotal = Object.values(metrics.scoreDistribution).reduce(
    (a, b) => a + b,
    0,
  );

  if (scoreTotal === 0 && merged.length === 0) return null;

  return (
    <div className="border border-zinc-800 rounded-md mb-4 bg-zinc-900">
      <div className="flex items-center px-4 py-2 hover:bg-zinc-800/40 transition-colors">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex-1 flex items-center justify-between text-left cursor-pointer"
          aria-expanded={open}
        >
          <span className="text-xs text-zinc-400">
            CVE Characteristics for{" "}
            <span className="text-zinc-200">&quot;{query}&quot;</span>
            <span className="text-zinc-600 ml-2">
              {total}
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
        <button
          type="button"
          onClick={() => setEmbedOpen(true)}
          title="Embed this view in an article"
          aria-label="Embed"
          className="ml-3 px-2 py-1 text-[10px] font-mono text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded hover:border-zinc-600 cursor-pointer transition-colors flex items-center gap-1"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="11"
            height="11"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden
          >
            <polyline points="16 18 22 12 16 6" />
            <polyline points="8 6 2 12 8 18" />
          </svg>
          embed
        </button>
      </div>
      <MetricsEmbedDialog
        open={embedOpen}
        onClose={() => setEmbedOpen(false)}
        query={query}
      />
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
