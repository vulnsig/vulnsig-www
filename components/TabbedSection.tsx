"use client";

import { useRef } from "react";
import { GalleryTab } from "./GalleryTab";
import { LegendTab } from "./LegendTab";
import { PackagesTab } from "./PackagesTab";
import { AboutTab } from "./AboutTab";
import { RecentCVETab } from "./RecentCVETab";
import { RecentKEVTab } from "./RecentKEVTab";
import { QuizTab } from "./QuizTab";
import { useBuilder } from "./BuilderContext";

const TABS = [
  { id: "cves", label: "CVEs" },
  { id: "kevs", label: "KEVs" },
  { id: "gallery", label: "Gallery" },
  { id: "quiz", label: "Quiz" },
  { id: "legend", label: "Legend" },
  { id: "tools", label: "Tools" },
  { id: "about", label: "About" },
] as const;

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
      {/* Tab bar — full width background, content constrained to max-w-6xl */}
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
              className={`flex-1 basis-1/4 sm:basis-0 px-4 text-sm font-[family-name:var(--font-mono)] font-semibold uppercase transition-colors cursor-pointer ${
                activeTab === tab.id
                  ? "text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
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
            {tab.id === "gallery" && <GalleryTab />}
            {tab.id === "quiz" && <QuizTab />}
            {tab.id === "legend" && <LegendTab />}
            {tab.id === "tools" && <PackagesTab />}
            {tab.id === "about" && <AboutTab />}
          </div>
        ))}
      </div>
    </section>
  );
}
