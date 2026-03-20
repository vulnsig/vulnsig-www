import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { DataProvider } from "@/components/DataContext";
import { BuilderProvider } from "@/components/BuilderContext";
import { ClientOnly } from "@/components/ClientOnly";
import { Masthead } from "@/components/Masthead";
import { BuilderBar } from "@/components/BuilderBar";
import { TabbedSection } from "@/components/TabbedSection";
import { HeroSectionCve } from "@/components/HeroSectionCve";
import { Footer } from "@/components/Footer";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";

interface CveApiResponse {
  id: string;
  vectorString: string;
  baseScore: number;
  description: string;
  product?: string;
  version?: string;
  published?: string;
  lastModified?: string;
}

async function fetchCve(cveId: string): Promise<CveApiResponse | null> {
  if (!API_BASE) return null;
  try {
    const res = await fetch(`${API_BASE}/cve/${cveId}`, {
      next: { revalidate: 3600 },
    });
    if (!res.ok) return null;
    return res.json() as Promise<CveApiResponse>;
  } catch {
    return null;
  }
}

interface PageProps {
  params: Promise<{ cveId: string }>;
  searchParams: Promise<Record<string, string | undefined>>;
}

export async function generateMetadata({
  params,
}: PageProps): Promise<Metadata> {
  const { cveId } = await params;
  const cve = await fetchCve(cveId);
  if (!cve) return { title: cveId };

  const title = `${cveId}: CVSS ${cve.baseScore}`;
  const description = cve.description;
  const imageUrl = `https://vulnsig.io/api/png?${new URLSearchParams({
    vector: cve.vectorString,
    score: String(cve.baseScore),
    size: "512",
  })}`;

  return {
    title,
    description,
    openGraph: {
      title,
      description,
      url: `https://vulnsig.io/cve/${cveId}`,
      siteName: "vulnsig",
      type: "website",
      images: [
        {
          url: imageUrl,
          width: 512,
          height: 512,
          alt: `${cveId} vulnerability glyph`,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [imageUrl],
    },
  };
}

export default async function CveLandingPage({ params }: PageProps) {
  const { cveId } = await params;
  const cve = await fetchCve(cveId);

  if (!cve) notFound();

  return (
    <Suspense>
      <DataProvider>
        <BuilderProvider
          initialVector={cve.vectorString}
          initialExpanded={true}
        >
          <div className="min-h-screen relative z-2">
            <Masthead />
            <ClientOnly>
              <HeroSectionCve
                cveId={cveId}
                vector={cve.vectorString}
                score={cve.baseScore}
                sentence={cve.description}
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
