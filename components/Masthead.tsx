import { VulnSigLogo } from "./VulnSigLogo";

export function Masthead() {
  return (
    <header className="fixed top-0 left-0 right-0 z-[60] py-2 px-4 flex items-center justify-center gap-4 bg-zinc-950/60 backdrop-blur-sm border-b border-zinc-800/50">
      <h1 className="flex items-center gap-2 text-3xl tracking-wide text-zinc-300 font-[family-name:var(--font-display)]">
        <VulnSigLogo size={28} color1="#d4d4d8" color2="#d4d4d8" />
        VulnSig
      </h1>
      <p className="text-md text-zinc-500 font-sans italic">more than a score</p>
    </header>
  );
}
