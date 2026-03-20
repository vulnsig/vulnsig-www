import { NextRequest, NextResponse } from "next/server";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";

export async function POST(request: NextRequest) {
  if (!API_BASE) {
    return NextResponse.json(
      { error: "Subscribe API is not configured" },
      { status: 500 },
    );
  }

  const body = await request.json();

  const res = await fetch(`${API_BASE}/subscribe`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => null);
  return NextResponse.json(data ?? {}, { status: res.status });
}
