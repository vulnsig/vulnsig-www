"use client";

import { useState, useEffect } from "react";
import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";
import { MetricPicker } from "./MetricPicker";
import { useBuilder } from "./BuilderContext";
import { calculateScore } from "vulnsig";

export function BuilderBar() {
  const { vector, setVector, expanded, setExpanded, builderRef } = useBuilder();
  const [inputValue, setInputValue] = useState(vector);
  const [score, setScore] = useState(10.0);
  // Sync input when vector changes externally (e.g., from gallery)
  useEffect(() => {
    setInputValue(vector);
  }, [vector]);

  // Recalculate score when vector changes
  useEffect(() => {
    setScore(calculateScore(vector));
  }, [vector]);

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const val = e.target.value;
    setInputValue(val);
    // Only update vector if it looks valid
    if (val.startsWith("CVSS:4.0/") && val.split("/").length >= 12) {
      setVector(val);
    }
  }

  function handleInputBlur() {
    // Reset to current vector if input is invalid
    setInputValue(vector);
  }

  function handleInputKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      (e.target as HTMLInputElement).blur();
    }
  }

  return (
    <div ref={builderRef}>
      <div
        className="sticky top-0 z-50 bg-zinc-900/95 backdrop-blur border-y border-zinc-800 builder-sticky"
      >
        {/* Collapsed bar */}
        <div className="max-w-6xl mx-auto flex items-center gap-4 px-4 py-3">
          <VulnSig vector={vector} size={100} score={score} />

          <input
            type="text"
            value={inputValue}
            onChange={handleInputChange}
            onBlur={handleInputBlur}
            onKeyDown={handleInputKeyDown}
            className="flex-1 min-w-0 bg-zinc-800/50 border border-zinc-700 rounded px-3 py-2 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
            spellCheck={false}
            aria-label="CVSS vector string"
          />

          <ScoreBadge score={score} />

          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded hover:border-zinc-600 cursor-pointer transition-colors"
            aria-expanded={expanded}
            aria-label={expanded ? "Collapse builder" : "Expand builder"}
          >
            {expanded ? "Collapse" : "Build"}
            <svg
              className={`w-3 h-3 transition-transform ${expanded ? "rotate-180" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Expanded metric picker */}
        {expanded && (
          <div className="border-t border-zinc-800">
            <div className="max-w-6xl mx-auto">
              <MetricPicker vector={vector} onChange={setVector} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
