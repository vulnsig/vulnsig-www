import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";
// NOTE: set via Amplify console Environment Variables (not Secrets tab);
// inlined at build time via next.config.ts `env` so it is available in the SSR Lambda.
const API_SECRET = process.env.API_SECRET ?? "";

export async function GET(request: NextRequest) {
  if (!API_BASE || !API_SECRET) {
    return NextResponse.json(
      { error: "Search API is not configured" },
      { status: 500 },
    );
  }

  const params = new URLSearchParams(request.nextUrl.searchParams);
  const kind = params.get("kind") === "id" ? "id" : "product";
  params.delete("kind");
  const upstreamPath = kind === "id" ? "/search/id" : "/search/product";
  const res = await fetch(`${API_BASE}${upstreamPath}?${params}`, {
    headers: { "x-api-key": API_SECRET },
    cache: "no-store",
  });

  const data = await res.json().catch(() => null);
  return NextResponse.json(data ?? {}, { status: res.status });
}
