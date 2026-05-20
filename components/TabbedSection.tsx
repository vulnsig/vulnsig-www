"use client";

import { useRef } from "react";
import { GalleryTab } from "./GalleryTab";
import { LegendTab } from "./LegendTab";
import { PackagesTab } from "./PackagesTab";
import { AboutTab } from "./AboutTab";
import { RecentCVETab } from "./RecentCVETab";
import { RecentKEVTab } from "./RecentKEVTab";
import { SearchTab } from "./SearchTab";
import { QuizTab } from "./QuizTab";
import { SubscribeTab } from "./SubscribeTab";
import { useBuilder } from "./BuilderContext";

const TABS = [
  { id: "cves", label: "CVEs" },
  { id: "kevs", label: "KEVs" },
  { id: "search", label: "Search" },
  { id: "gallery", label: "Gallery" },
  { id: "legend", label: "Legend" },
  { id: "quiz", label: "Quiz" },
  { id: "tools", label: "Tools" },
  { id: "about", label: "About" },
  { id: "subscribe", label: "Subscribe" },
] as const;

// Per-breakpoint row sizing — must match basis-1/3 / sm:basis-1/5 below.
const COLS_NARROW = 3;
const COLS_WIDE = 5;
const padCount = (n: number, cols: number) => (cols - (n % cols)) % cols;
const NARROW_PADS = padCount(TABS.length, COLS_NARROW);
const WIDE_PADS = padCount(TABS.length, COLS_WIDE);

export function TabbedSection() {
  const { activeTab, setActiveTab } = useBuilder();
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  function handleKeyDown(e: React.KeyboardEvent) {
    const idx = TABS.findIndex((t) => t.id === activeTab);
    if (e.key === "ArrowRight") {
      e.preventDefault();
      const next = TABS[(idx + 1) % TABS.length];
      setActiveTab(next.id);
      tabRefs.current[next.id]?.focus();
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      const prev = TABS[(idx - 1 + TABS.length) % TABS.length];
      setActiveTab(prev.id);
      tabRefs.current[prev.id]?.focus();
    }
  }

  return (
    <section className="w-full">
      {/* Tab bar: full width background, content constrained to max-w-6xl */}
      <div
        className="w-full bg-zinc-900 border-b border-zinc-800"
        style={{
          background:
            "repeating-linear-gradient(45deg, #18181b, #18181b 4px, #1f1f23 4px, #1f1f23 8px)",
        }}
        role="tablist"
        onKeyDown={handleKeyDown}
      >
        <div className="max-w-6xl mx-auto px-4 flex flex-wrap py-3 gap-y-3">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              ref={(el) => {
                tabRefs.current[tab.id] = el;
              }}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`panel-${tab.id}`}
              tabIndex={activeTab === tab.id ? 0 : -1}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 basis-1/3 sm:basis-1/5 px-1 text-sm font-[family-name:var(--font-mono)] font-semibold uppercase transition-colors cursor-pointer ${
                activeTab === tab.id
                  ? "text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
          {/* Empty placeholders so the last row matches a full row's column count. */}
          {Array.from({ length: Math.max(NARROW_PADS, WIDE_PADS) }).map(
            (_, i) => {
              const showOnNarrow = i < NARROW_PADS;
              const showOnWide = i < WIDE_PADS;
              const visibility =
                showOnNarrow && showOnWide
                  ? ""
                  : showOnNarrow
                    ? "sm:hidden"
                    : "hidden sm:block";
              return (
                <div
                  key={`pad-${i}`}
                  aria-hidden
                  className={`flex-1 basis-1/3 sm:basis-1/5 px-1 ${visibility}`}
                />
              );
            },
          )}
        </div>
      </div>

      {/* Tab panels */}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {TABS.map((tab) => (
          <div
            key={tab.id}
            id={`panel-${tab.id}`}
            role="tabpanel"
            aria-labelledby={tab.id}
            hidden={activeTab !== tab.id}
          >
            {tab.id === "cves" && <RecentCVETab />}
            {tab.id === "kevs" && <RecentKEVTab />}
            {tab.id === "search" && <SearchTab />}
            {tab.id === "gallery" && <GalleryTab />}
            {tab.id === "legend" && <LegendTab />}
            {tab.id === "quiz" && <QuizTab />}
            {tab.id === "tools" && <PackagesTab />}
            {tab.id === "about" && <AboutTab />}
            {tab.id === "subscribe" && <SubscribeTab />}
          </div>
        ))}
      </div>
    </section>
  );
}
