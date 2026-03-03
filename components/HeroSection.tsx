"use client";

import { HeroGlyph } from "./HeroGlyph";
import { useBuilder } from "./BuilderContext";

export function HeroSection() {
  const { vector, selectedVuln, heroRef } = useBuilder();
  const vuln = selectedVuln ?? { name: "", cve: null, vector, description: "" };

  return (
    <section className="w-full pt-16 pb-4 px-4">
      <div className="max-w-6xl mx-auto">

        <div ref={heroRef} className="flex justify-center">
          <HeroGlyph vuln={vuln} />
        </div>
      </div>
    </section>
  );
}
