import { NextRequest, NextResponse } from "next/server";
import sharp from "sharp";
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

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const q = (searchParams.get("q") ?? "").trim();
  const widthParam = searchParams.get("width");
  const densityParam = searchParams.get("density");

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

  const density = densityParam ? parseInt(densityParam, 10) : 96;
  if (isNaN(density) || density < 72 || density > 600) {
    return NextResponse.json(
      {
        error: "Invalid density",
        detail: "density must be a number between 72 and 600",
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

  const upstreamParams = new URLSearchParams({ q, limit: "1" });
  let data: UpstreamSearchResponse | null = null;
  try {
    const res = await fetch(
      `${API_BASE}/search/product?${upstreamParams}`,
      { headers: { "x-api-key": API_SECRET }, cache: "no-store" },
    );
    if (!res.ok) {
      return NextResponse.json(
        { error: `Upstream search failed (${res.status})` },
        { status: 502 },
      );
    }
    data = (await res.json()) as UpstreamSearchResponse;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "Upstream search failed", detail },
      { status: 502 },
    );
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

  try {
    const png = await sharp(Buffer.from(svg), { density })
      .ensureAlpha()
      .png()
      .toBuffer();
    return new Response(new Uint8Array(png), {
      headers: {
        "Content-Type": "image/png",
        "Cache-Control": CACHE_HEADER,
      },
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "PNG conversion failed", detail },
      { status: 500 },
    );
  }
}
