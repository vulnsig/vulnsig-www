export function Masthead() {
  return (
    <header className="fixed top-0 left-0 right-0 z-[60] py-2 px-4 flex items-baseline justify-center gap-4 bg-zinc-950/60 backdrop-blur-sm border-b border-zinc-800/50">
      <h1 className="text-3xl tracking-wide text-zinc-300 font-[family-name:var(--font-display)]">
        VulnSig
      </h1>
      <p className="text-md text-zinc-500 font-sans">more than a score</p>
    </header>
  );
}
