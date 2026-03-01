"use client";

import { useRef, useState, useEffect, useCallback } from "react";
import { HERO_VULNERABILITIES } from "@/data/vulnerabilities";
import { HeroGlyph } from "./HeroGlyph";

export function HeroSection() {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [activeIndex, setActiveIndex] = useState(0);

  const scrollTo = useCallback((index: number) => {
    const container = scrollRef.current;
    if (!container) return;
    const child = container.children[index] as HTMLElement;
    if (child) {
      container.scrollTo({ left: child.offsetLeft, behavior: "smooth" });
    }
  }, []);

  useEffect(() => {
    const container = scrollRef.current;
    if (!container) return;

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const idx = Array.from(container.children).indexOf(entry.target as HTMLElement);
            if (idx >= 0) setActiveIndex(idx);
          }
        }
      },
      { root: container, threshold: 0.6 }
    );

    for (const child of Array.from(container.children)) {
      observer.observe(child);
    }
    return () => observer.disconnect();
  }, []);

  return (
    <section className="w-full py-8 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Headline */}
        <div className="text-center">
          <h1 className="text-4xl sm:text-4xl lg:text-6xl font-bold tracking-tight mb-2">
            CVSS is more than a number
          </h1>
          <p className="text-lg sm:text-xl text-zinc-400 max-w-2xl mx-auto leading-relaxed">
            VulnSig translate CVSS vectors into a compact visual glyph, encoding every CVSS metric into a specific visual characteristic.
          </p>
        </div>

        {/* Hero glyphs — horizontal snap scroll */}
        <div className="relative">
          <div
            ref={scrollRef}
            className="flex overflow-x-auto snap-x snap-mandatory gap-0 scrollbar-hide pb-4 -mx-4 px-4"
          >
            {HERO_VULNERABILITIES.map((vuln) => (
              <div
                key={vuln.cve ?? vuln.name}
                className="flex-none w-full snap-center flex justify-center"
              >
                <HeroGlyph vuln={vuln} />
              </div>
            ))}
          </div>
          {/* Clickable dot indicators */}
          <div className="flex justify-center gap-2.5 mt-4">
            {HERO_VULNERABILITIES.map((_, i) => (
              <button
                key={i}
                onClick={() => scrollTo(i)}
                aria-label={`Go to glyph ${i + 1}`}
                className={`w-2 h-2 rounded-full transition-all duration-200 cursor-pointer ${
                  i === activeIndex
                    ? "bg-zinc-300 scale-125"
                    : "bg-zinc-700 hover:bg-zinc-500"
                }`}
              />
            ))}
          </div>
          <p className="text-center text-xs text-zinc-600 mt-2 font-mono">
            scroll to explore
          </p>
        </div>
      </div>
    </section>
  );
}
