import { BuilderProvider } from "@/components/BuilderContext";
import { ClientOnly } from "@/components/ClientOnly";
import { HeroSection } from "@/components/HeroSection";
import { BuilderBar } from "@/components/BuilderBar";
import { TabbedSection } from "@/components/TabbedSection";

export default function Home() {
  return (
    <BuilderProvider>
      <div className="min-h-screen relative z-2">
        <ClientOnly>
          <HeroSection />
          <BuilderBar />
          <TabbedSection />
        </ClientOnly>

        {/* Footer */}
        <footer className="border-t border-zinc-800 py-8 px-4">
          <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-zinc-600">
            <p className="font-mono">vulnsig.io</p>
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
            </div>
          </div>
        </footer>
      </div>
    </BuilderProvider>
  );
}
