"use client";

import { VULNERABILITIES } from "@/data/vulnerabilities";
import { HeroGlyph } from "./HeroGlyph";
import { useBuilder } from "./BuilderContext";

export function HeroSection() {
  const { vector, heroRef } = useBuilder();
  const match = VULNERABILITIES.find((v) => v.vector === vector);
  const vuln = match ?? { name: "", cve: null, vector, description: "" };

  return (
    <section className="w-full py-4 px-4">
      <div className="max-w-6xl mx-auto">
        {/* Headline */}
        <div className="text-center mb-4">
          <h1 className="text-4xl lg:text-5xl font-bold tracking-tight mb-4">
            CVSS is more than a number
          </h1>
          <p className="text-lg sm:text-xl text-zinc-400 max-w-2xl mx-auto">
            VulnSig translate CVSS vectors into a compact visual glyph, encoding
            every CVSS metric into a specific visual characteristic.
          </p>
        </div>

        {/* Hero glyph driven by builder vector */}
        <div ref={heroRef} className="flex justify-center">
          <HeroGlyph vuln={vuln} />
        </div>
      </div>
    </section>
  );
}
