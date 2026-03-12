import { NextRequest, NextResponse } from "next/server";
import { renderGlyph } from "vulnsig";
import sharp from "sharp";

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const vector = searchParams.get("vector");
  const sizeParam = searchParams.get("size");
  const scoreParam = searchParams.get("score");
  const densityParam = searchParams.get("density");

  if (!vector) {
    return NextResponse.json(
      {
        error: "Missing required parameter",
        detail: "The 'vector' query parameter is required",
      },
      { status: 400 },
    );
  }

  if (!vector.startsWith("CVSS:")) {
    return NextResponse.json(
      {
        error: "Invalid CVSS vector",
        detail: "Vector must start with 'CVSS:'",
      },
      { status: 400 },
    );
  }

  const size = sizeParam ? parseInt(sizeParam, 10) : 120;
  if (isNaN(size) || size < 16 || size > 1024) {
    return NextResponse.json(
      {
        error: "Invalid size",
        detail: "Size must be a number between 16 and 1024",
      },
      { status: 400 },
    );
  }

  const score = scoreParam ? parseFloat(scoreParam) : undefined;
  if (score !== undefined && (isNaN(score) || score < 0 || score > 10)) {
    return NextResponse.json(
      {
        error: "Invalid score",
        detail: "Score must be a number between 0 and 10",
      },
      { status: 400 },
    );
  }

  const density = densityParam ? parseInt(densityParam, 10) : 72;
  if (isNaN(density) || density < 72 || density > 600) {
    return NextResponse.json(
      {
        error: "Invalid density",
        detail: "Density must be a number between 72 and 600",
      },
      { status: 400 },
    );
  }

  let svg: string;
  try {
    svg = renderGlyph({ vector, size, score: score ?? null });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "Invalid CVSS vector", detail: message },
      { status: 400 },
    );
  }

  try {
    const png = await sharp(Buffer.from(svg), { density })
      .ensureAlpha()
      .png()
      .toBuffer();

    return new Response(new Uint8Array(png), {
      headers: {
        "Content-Type": "image/png",
        "Cache-Control": "public, max-age=31536000, immutable",
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json(
      { error: "PNG conversion failed", detail: message },
      { status: 500 },
    );
  }
}
