"use client";

import { useState, useRef, useEffect } from "react";
import { GalleryTab } from "./GalleryTab";
import { LegendTab } from "./LegendTab";
import { PackagesTab } from "./PackagesTab";

const TABS = [
  { id: "gallery", label: "Gallery" },
  { id: "legend", label: "Legend" },
  { id: "packages", label: "Packages & API" },
] as const;

type TabId = (typeof TABS)[number]["id"];

export function TabbedSection() {
  const [activeTab, setActiveTab] = useState<TabId>("gallery");
  const [underline, setUnderline] = useState({ left: 0, width: 0 });
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const tabBarRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = tabRefs.current[activeTab];
    if (el) {
      setUnderline({ left: el.offsetLeft, width: el.offsetWidth });
    }
  }, [activeTab]);

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
    <section className="w-full py-4 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Tab bar */}
        <div
          ref={tabBarRef}
          className="relative border-b border-zinc-800 mb-8"
          role="tablist"
          onKeyDown={handleKeyDown}
        >
          <div className="flex gap-0">
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
                onClick={() => {
                  setActiveTab(tab.id);
                  tabBarRef.current?.scrollIntoView({
                    behavior: "smooth",
                    block: "start",
                  });
                }}
                className={`px-5 py-3 text-sm font-mono transition-colors cursor-pointer ${
                  activeTab === tab.id
                    ? "text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
          {/* Underline indicator */}
          <div
            className="absolute bottom-0 h-px bg-zinc-100 tab-underline"
            style={{ left: underline.left, width: underline.width }}
          />
        </div>

        {/* Tab panels */}
        {TABS.map((tab) => (
          <div
            key={tab.id}
            id={`panel-${tab.id}`}
            role="tabpanel"
            aria-labelledby={tab.id}
            hidden={activeTab !== tab.id}
          >
            {tab.id === "gallery" && <GalleryTab />}
            {tab.id === "legend" && <LegendTab />}
            {tab.id === "packages" && <PackagesTab />}
          </div>
        ))}
      </div>
    </section>
  );
}
