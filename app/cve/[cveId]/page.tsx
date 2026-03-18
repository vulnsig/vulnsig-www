import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Suspense } from "react";
import { DataProvider } from "@/components/DataContext";
import { BuilderProvider } from "@/components/BuilderContext";
import { ClientOnly } from "@/components/ClientOnly";
import { Masthead } from "@/components/Masthead";
import { BuilderBar } from "@/components/BuilderBar";
import { TabbedSection } from "@/components/TabbedSection";
import { HeroSectionCve } from "@/components/HeroSectionCve";
import { Footer } from "@/components/Footer";
import { decodeVector } from "@/lib/vectorUrl";

interface PageProps {
  params: Promise<{ cveId: string }>;
  searchParams: Promise<{ v?: string; s?: string; d?: string }>;
}

export async function generateMetadata({
  params,
  searchParams,
}: PageProps): Promise<Metadata> {
  const { cveId } = await params;
  const { v, s, d } = await searchParams;
  const vector = v ? decodeVector(v) : undefined;
  const title = s ? `${cveId}: CVSS ${s}` : cveId;
  const description = d ?? "";
  const imageUrl = vector
    ? `https://vulnsig.io/api/png?${new URLSearchParams({
        vector,
        ...(s ? { score: s } : {}),
        size: "512",
      })}`
    : undefined;

  return {
    title,
    description,
    openGraph: {
      title,
      description,
      url: `https://vulnsig.io/cve/${cveId}`,
      siteName: "vulnsig",
      type: "website",
      ...(imageUrl
        ? {
            images: [
              {
                url: imageUrl,
                width: 512,
                height: 512,
                alt: `${cveId} vulnerability glyph`,
              },
            ],
          }
        : {}),
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      ...(imageUrl ? { images: [imageUrl] } : {}),
    },
  };
}

export default async function CveLandingPage({
  params,
  searchParams,
}: PageProps) {
  const { cveId } = await params;
  const { v, s, d } = await searchParams;

  if (!v) redirect("/");

  const vector = decodeVector(v);
  const score = s ? parseFloat(s) : undefined;
  const sentence = d || undefined;

  return (
    <Suspense>
      <DataProvider>
        <BuilderProvider initialVector={vector} initialExpanded={true}>
          <div className="min-h-screen relative z-2">
            <Masthead />
            <ClientOnly>
              <HeroSectionCve
                cveId={cveId}
                vector={vector}
                score={score}
                sentence={sentence}
              />
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
