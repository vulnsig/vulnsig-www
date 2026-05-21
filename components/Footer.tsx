"use client";

export function Footer() {
  return (
    <footer className="border-t border-zinc-800 py-8 px-4">
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-zinc-600">
        <button
          type="button"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="font-mono hover:text-zinc-400 transition-colors cursor-pointer"
          aria-label="Scroll to top"
        >
          vulnsig.io
        </button>
        <div className="flex gap-4 font-mono">
          <a
            href="https://github.com/vulnsig"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-zinc-400 transition-colors"
          >
            GitHub
          </a>
          <a
            href="https://www.npmjs.com/package/vulnsig"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-zinc-400 transition-colors"
          >
            npm
          </a>
          <a
            href="https://pypi.org/project/vulnsig"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-zinc-400 transition-colors"
          >
            PyPI
          </a>
          <a
            href="https://crates.io/crates/vulnsig"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-zinc-400 transition-colors"
          >
            crates.io
          </a>
        </div>
      </div>
    </footer>
  );
}
