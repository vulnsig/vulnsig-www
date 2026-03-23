import { NextRequest, NextResponse } from "next/server";
import getConfig from "next/config";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";

function getApiSecret(): string {
  const { serverRuntimeConfig } = getConfig() ?? {};
  return serverRuntimeConfig?.apiSecret ?? "";
}

export async function POST(request: NextRequest) {
  const API_SECRET = getApiSecret();
  if (!API_BASE || !API_SECRET) {
    return NextResponse.json(
      { error: "Subscribe API is not configured" },
      { status: 500 },
    );
  }

  const body = await request.json();

  const res = await fetch(`${API_BASE}/subscribe`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": API_SECRET,
    },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => null);
  return NextResponse.json(data ?? {}, { status: res.status });
}
