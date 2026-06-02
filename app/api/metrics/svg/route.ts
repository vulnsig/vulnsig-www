import { NextRequest, NextResponse } from "next/server";
import { renderDistributionSvg } from "@/lib/distributionSvg";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";
const API_SECRET = process.env.API_SECRET ?? "";

interface UpstreamMetrics {
  scoreDistribution?: Record<string, number>;
  vectorDistribution?: Record<string, Record<string, number>>;
}
interface UpstreamSearchResponse {
  total?: number;
  truncated?: boolean;
  metrics?: UpstreamMetrics;
}

const CACHE_HEADER =
  "public, max-age=3600, s-maxage=3600, stale-while-revalidate=86400";

function placeholderSvg(width: number, message: string): string {
  return renderDistributionSvg({
    query: message,
    total: 0,
    truncated: false,
    scoreDistribution: {},
    vectorDistribution: {},
    width,
    generatedAt: new Date(),
  });
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const q = (searchParams.get("q") ?? "").trim();
  const widthParam = searchParams.get("width");

  if (!q) {
    return NextResponse.json(
      {
        error: "Missing required parameter",
        detail: "The 'q' query parameter is required",
      },
      { status: 400 },
    );
  }

  const width = widthParam ? parseInt(widthParam, 10) : 720;
  if (isNaN(width) || width < 320 || width > 1600) {
    return NextResponse.json(
      {
        error: "Invalid width",
        detail: "width must be a number between 320 and 1600",
      },
      { status: 400 },
    );
  }

  if (!API_BASE || !API_SECRET) {
    return NextResponse.json(
      { error: "Metrics API is not configured" },
      { status: 500 },
    );
  }

  // Upstream returns metrics in the same payload as search hits. We don't need
  // items here so caller can keep limit=1 to minimize bandwidth — the backend
  // still computes metrics over the full result set.
  const upstreamParams = new URLSearchParams({ q, limit: "1" });
  let data: UpstreamSearchResponse | null = null;
  try {
    const res = await fetch(
      `${API_BASE}/search/product?${upstreamParams}`,
      { headers: { "x-api-key": API_SECRET }, cache: "no-store" },
    );
    if (!res.ok) {
      return new Response(placeholderSvg(width, "data temporarily unavailable"), {
        status: 200,
        headers: {
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=60",
        },
      });
    }
    data = (await res.json()) as UpstreamSearchResponse;
  } catch {
    return new Response(placeholderSvg(width, "data temporarily unavailable"), {
      status: 200,
      headers: {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "public, max-age=60",
      },
    });
  }

  const metrics = data?.metrics ?? {};
  const svg = renderDistributionSvg({
    query: q,
    total: data?.total ?? 0,
    truncated: data?.truncated ?? false,
    scoreDistribution: metrics.scoreDistribution ?? {},
    vectorDistribution: metrics.vectorDistribution ?? {},
    width,
    generatedAt: new Date(),
  });

  return new Response(svg, {
    headers: {
      "Content-Type": "image/svg+xml",
      "Cache-Control": CACHE_HEADER,
    },
  });
}
