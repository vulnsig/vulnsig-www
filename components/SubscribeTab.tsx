"use client";

import { useState } from "react";

type Status = "idle" | "submitting" | "success" | "error";

export function SubscribeTab() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [errorMsg, setErrorMsg] = useState("");

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
      <p className="text-sm text-zinc-400 leading-relaxed mb-6">
        A weekday newsletter of notable recent CVEs and KEVs, accompanied by a
        concise, LLM-generated summary and trend commentary. Subscribe to get
        new vulnerability details and glyphs delivered to your inbox.
        Unsubscribe anytime; no marketing or third-party emails.
      </p>

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
    </div>
  );
}
