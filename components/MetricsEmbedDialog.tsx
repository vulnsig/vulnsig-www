"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface Props {
  open: boolean;
  onClose: () => void;
  query: string;
}

const SITE_ORIGIN = process.env.NEXT_PUBLIC_SITE_ORIGIN ?? "https://vulnsig.io";

function buildSvgUrl(query: string): string {
  return `${SITE_ORIGIN}/api/metrics/svg?q=${encodeURIComponent(query)}`;
}
function buildPngUrl(query: string): string {
  return `${SITE_ORIGIN}/api/metrics/png?q=${encodeURIComponent(query)}`;
}
function buildHtmlSnippet(query: string): string {
  const url = buildSvgUrl(query);
  return `<img\n  src="${url}"\n  alt="CVE characteristics for ${query}"\n  style="max-width: 100%; height: auto;"\n/>`;
}

export function MetricsEmbedDialog({ open, onClose, query }: Props) {
  const overlayRef = useRef<HTMLDivElement>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const svgUrl = buildSvgUrl(query);
  const pngUrl = buildPngUrl(query);
  const htmlSnippet = buildHtmlSnippet(query);

  async function copy(field: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  }

  function handleOverlayClick(e: React.MouseEvent<HTMLDivElement>) {
    if (e.target === overlayRef.current) onClose();
  }

  return createPortal(
    <div
      ref={overlayRef}
      className="fixed inset-0 bg-black/60 z-[200] flex items-center justify-center p-4"
      onClick={handleOverlayClick}
    >
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 max-w-2xl w-full">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-zinc-200">
              Embed CVE Characteristics
            </h2>
            <p className="text-xs text-zinc-500 mt-1">
              Live snapshot for{" "}
              <span className="font-mono text-zinc-300">
                &quot;{query}&quot;
              </span>{" "}
              — refreshes as new CVEs land.
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="space-y-4">
          <Field
            label="HTML embed"
            value={htmlSnippet}
            multiline
            copied={copiedField === "html"}
            onCopy={() => copy("html", htmlSnippet)}
          />
          <Field
            label="Image URL (SVG)"
            value={svgUrl}
            copied={copiedField === "svg"}
            onCopy={() => copy("svg", svgUrl)}
          />
          <div className="text-[11px] text-zinc-500">
            Or use{" "}
            <a
              href={pngUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-zinc-300 hover:text-zinc-100 underline underline-offset-2"
            >
              PNG
            </a>{" "}
            for places that don&apos;t accept SVG (e.g. some social previews).
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}

function Field({
  label,
  value,
  multiline,
  copied,
  onCopy,
}: {
  label: string;
  value: string;
  multiline?: boolean;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <label className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
          {label}
        </label>
        <button
          onClick={onCopy}
          className="text-[10px] font-mono text-zinc-400 hover:text-zinc-200 transition-colors cursor-pointer"
        >
          {copied ? "copied ✓" : "copy"}
        </button>
      </div>
      {multiline ? (
        <pre className="bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs text-zinc-300 font-mono overflow-x-auto whitespace-pre">
          {value}
        </pre>
      ) : (
        <input
          type="text"
          readOnly
          value={value}
          onFocus={(e) => e.currentTarget.select()}
          className="w-full bg-zinc-950 border border-zinc-800 rounded px-3 py-2 text-xs text-zinc-300 font-mono focus:outline-none focus:border-zinc-600"
        />
      )}
    </div>
  );
}
