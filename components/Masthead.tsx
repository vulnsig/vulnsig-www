"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { VulnSigLogo } from "./VulnSigLogo";

const DIM = "#939598";
const LIT = "#d4d4d8";
const INTERVAL = 3 * 60_000; // every 3 minutes
const STEP = 180; // ms per phase

// Phases: 0 = top+right, 1 = right+left, 2 = left+top, null = idle
type Phase = 0 | 1 | 2 | null;

const colors: Record<number, [string, string, string]> = {
  0: [LIT, LIT, DIM], // top + right
  1: [DIM, LIT, LIT], // right + left
  2: [LIT, DIM, LIT], // left + top
};

export function Masthead() {
  const [phase, setPhase] = useState<Phase>(null);

  useEffect(() => {
    const REPS = 2;
    const cycle = () => {
      for (let r = 0; r < REPS; r++) {
        const off = r * STEP * 3;
        setTimeout(() => setPhase(0), off);
        setTimeout(() => setPhase(1), off + STEP);
        setTimeout(() => setPhase(2), off + STEP * 2);
      }
      setTimeout(() => setPhase(null), REPS * STEP * 3);
    };

    cycle();
    const id = setInterval(cycle, INTERVAL);
    return () => clearInterval(id);
  }, []);

  const [c1, c2, c3] = phase !== null ? colors[phase] : [LIT, LIT, DIM];

  return (
    <header className="fixed top-0 left-0 right-0 z-[60] py-2 px-4 flex items-center justify-center gap-2 bg-zinc-950/60 backdrop-blur-sm border-b border-zinc-800/40">
      <Link
        href="/"
        className="flex items-center gap-2 text-3xl tracking-wide text-zinc-300 font-[family-name:var(--font-display)]"
      >
        <VulnSigLogo size={22} color1={c1} color2={c2} color3={c3} />
        VulnSig
      </Link>
      <p className="text-md text-zinc-500 font-sans italic">
        more than a score
      </p>
    </header>
  );
}
