import { Suspense } from "react";
import { DataProvider } from "@/components/DataContext";
import { BuilderProvider } from "@/components/BuilderContext";
import { ClientOnly } from "@/components/ClientOnly";
import { Masthead } from "@/components/Masthead";
import { HeroSection } from "@/components/HeroSection";
import { BuilderBar } from "@/components/BuilderBar";
import { TabbedSection } from "@/components/TabbedSection";
import { Footer } from "@/components/Footer";

export default function Home() {
  return (
    <Suspense>
      <DataProvider>
        <BuilderProvider>
          <div className="min-h-screen relative z-2">
            <Masthead />
            <ClientOnly>
              <HeroSection />
              <BuilderBar />
              <TabbedSection />
            </ClientOnly>

            <Footer />
          </div>
        </BuilderProvider>
      </DataProvider>
    </Suspense>
  );
}
