"use client";

import { useState, useEffect, useRef } from "react";
import { VulnSig } from "vulnsig-react";
import { ScoreBadge } from "./ScoreBadge";
import { MetricPicker } from "./MetricPicker";
import { useBuilder } from "./BuilderContext";
import { calculateScore } from "vulnsig";

export function BuilderBar() {
  const {
    vector,
    setVector,
    expanded,
    setExpanded,
    builderRef,
    navigateToPackageSection,
  } = useBuilder();
  const [inputValue, setInputValue] = useState(vector);
  const vectorRef = useRef(vector);
  const score = calculateScore(vector);

  // Keep ref in sync so blur handler always sees latest vector
  useEffect(() => {
    vectorRef.current = vector;
  }, [vector]);

  // Sync input when vector changes externally (e.g., from gallery)
  useEffect(() => {
    setInputValue(vector);
  }, [vector]);

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const val = e.target.value;
    setInputValue(val);
    // Only update vector if it looks valid
    const parts = val.split("/");
    if (
      (val.startsWith("CVSS:4.0/") && parts.length >= 12) ||
      (val.startsWith("CVSS:3.1/") && parts.length >= 9) ||
      (val.startsWith("CVSS:3.0/") && parts.length >= 9)
    ) {
      setVector(val);
    }
  }

  function handleInputBlur() {
    // Reset to current vector if input is invalid — use ref for latest value
    setInputValue(vectorRef.current);
  }

  function handleInputKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter") {
      (e.target as HTMLInputElement).blur();
    }
  }

  return (
    <div ref={builderRef}>
      <div className="sticky top-0 z-50 bg-zinc-900 backdrop-blur border-y border-zinc-800 builder-sticky">
        {/* Collapsed bar */}
        <div className="max-w-6xl mx-auto px-4">
          {/* Row 1: glyph + vector input + score + collapse */}
          <div className="flex items-center pt-2">
            <VulnSig vector={vector} size={50} score={score} />

            <input
              type="text"
              value={inputValue}
              onChange={handleInputChange}
              onBlur={handleInputBlur}
              onKeyDown={handleInputKeyDown}
              className="flex-1 min-w-0 bg-zinc-800/50 border border-zinc-700 rounded px-2 py-1.5 ml-2 mr-4 font-mono text-xs text-zinc-300 focus:outline-none focus:border-zinc-500"
              spellCheck={false}
              aria-label="CVSS vector string"
            />

            <ScoreBadge score={score} size="sm" />

            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center px-3 py-1.5 ml-4 text-xs font-mono text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded hover:border-zinc-600 cursor-pointer transition-colors"
              aria-expanded={expanded}
              aria-label={expanded ? "Collapse builder" : "Expand builder"}
            >
              <span className="inline-grid [&>*]:col-start-1 [&>*]:row-start-1">
                <span className="invisible">Collapse</span>
                <span className="text-center">
                  {expanded ? "Collapse" : "Build"}
                </span>
              </span>
              <svg
                className={`w-3 h-3 transition-transform ${expanded ? "rotate-180" : ""}`}
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M19 9l-7 7-7-7"
                />
              </svg>
            </button>
          </div>

          {/* Row 2: get-from buttons */}
          <div className="flex items-center justify-end gap-2 pb-4">
            <span className="text-xs font-mono text-zinc-600">
              get this glyph via
            </span>
            <div className="flex items-center border border-zinc-700 rounded overflow-hidden">
              <a
                href={`/api/svg?vector=${encodeURIComponent(vector)}${score !== null ? `&score=${score}` : ""}`}
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors border-r border-zinc-700"
              >
                URL
              </a>
              <button
                onClick={() => navigateToPackageSection("pkg-typescript")}
                className="px-3 py-1.5 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors cursor-pointer border-r border-zinc-700"
              >
                TypeScript
              </button>
              <button
                onClick={() => navigateToPackageSection("pkg-python")}
                className="px-3 py-1.5 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors cursor-pointer border-r border-zinc-700"
              >
                Python
              </button>
              <button
                onClick={() => navigateToPackageSection("pkg-rest-api")}
                className="px-3 py-1.5 text-xs font-mono text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors cursor-pointer"
              >
                REST API
              </button>
            </div>
          </div>
        </div>

        {/* Expanded metric picker */}
        {expanded && (
          <div className="border-t border-zinc-800">
            <div className="max-w-6xl mx-auto">
              <MetricPicker
                vector={vector}
                onChange={(v) => setVector(v, true)}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
