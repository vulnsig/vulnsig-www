"use client";

import { useState } from "react";
import { createPortal } from "react-dom";

type Status = "idle" | "submitting" | "success" | "error";

const CVE_DATA_URL = process.env.NEXT_PUBLIC_CVE_DATA_URL ?? null;
const DIGEST_URL = CVE_DATA_URL
  ? new URL("/digest/latest.html", CVE_DATA_URL).href
  : null;

function DigestModal({ onClose }: { onClose: () => void }) {
  return createPortal(
    <div
      className="fixed inset-0 bg-black/70 z-[200] flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-zinc-900 border border-zinc-800 rounded-lg w-full max-w-3xl flex flex-col"
        style={{ height: "80vh" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
          <span className="text-sm font-semibold text-zinc-200">
            Latest VulnSig Digest
          </span>
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
        <iframe
          src={DIGEST_URL!}
          className="flex-1 w-full rounded-b-lg"
          title="Latest VulnSig Digest"
        />
      </div>
    </div>,
    document.body,
  );
}

export function SubscribeTab() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [digestOpen, setDigestOpen] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("submitting");
    setErrorMsg("");

    try {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(data?.error ?? `Request failed (${res.status})`);
      }
      setStatus("success");
    } catch (err) {
      setStatus("error");
      setErrorMsg(err instanceof Error ? err.message : "Something went wrong");
    }
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h3 className="text-lg font-semibold mb-6">VulnSig Digest</h3>
      <p className="text-sm text-zinc-400 leading-relaxed mb-4">
        A weekday newsletter of notable recent CVEs and KEVs, accompanied by a
        concise, LLM-generated summary and trend commentary. Subscribe to get
        new vulnerability details and glyphs delivered to your inbox.
        Unsubscribe anytime; no marketing or third-party emails.
      </p>

      {DIGEST_URL && (
        <div className="mb-6">
          <button
            onClick={() => setDigestOpen(true)}
            className="text-xs font-mono text-zinc-500 hover:text-zinc-300 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
          >
            Read it now
          </button>
        </div>
      )}

      {status === "success" ? (
        <p className="text-sm text-indigo-300/90">
          Check your email to confirm your subscription.
        </p>
      ) : (
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="email"
            required
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="flex-1 px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500"
          />
          <button
            type="submit"
            disabled={status === "submitting" || !email.trim()}
            className="px-4 py-1.5 text-sm font-semibold bg-zinc-700 hover:bg-zinc-600 disabled:opacity-50 disabled:cursor-not-allowed rounded text-zinc-200 transition-colors cursor-pointer"
          >
            {status === "submitting" ? "Subscribing\u2026" : "Subscribe"}
          </button>
        </form>
      )}

      {status === "error" && (
        <p className="mt-2 text-sm text-red-400">{errorMsg}</p>
      )}

      {digestOpen && <DigestModal onClose={() => setDigestOpen(false)} />}
    </div>
  );
}
