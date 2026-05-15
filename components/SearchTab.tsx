"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { VirtuosoGrid } from "react-virtuoso";
import { useBuilder } from "./BuilderContext";
import { GlyphCard } from "./GlyphCard";

type SortMode = "score" | "date";
type SearchKind = "product" | "id";

interface SearchItem {
  id: string;
  product?: string;
  baseScore: number | string;
  published: string;
  description: string;
  version?: string;
  vectorString?: string;
}

interface SearchResponse {
  items: SearchItem[];
  total: number;
  limit: number;
  nextCursor: string | null;
}

function formatDateTime(iso: string): string {
  const utcIso = iso.endsWith("Z") || /T.*[+-]/.test(iso) ? iso : `${iso}Z`;
  return new Date(utcIso).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function readSortFromUrl(value: string | null): SortMode {
  return value === "date" ? "date" : "score";
}

function readKindFromUrl(value: string | null): SearchKind {
  return value === "id" ? "id" : "product";
}

const MIN_LEN: Record<SearchKind, number> = { product: 2, id: 1 };

const PLACEHOLDER: Record<SearchKind, string> = {
  product: "Search by product name (e.g. react, openssl, lz4_flex)",
  id: "Search by CVE id (e.g. CVE-2024-1234 or 2024-1234)",
};

export function SearchTab() {
  const { loadVector } = useBuilder();
  const router = useRouter();
  const searchParams = useSearchParams();

  const initialQ = (searchParams.get("q") ?? "").trim();

  const [query, setQuery] = useState(initialQ);
  // committedQuery starts empty so the URL-sync effect always fires once on
  // mount and runs the search for a deep-linked ?q=… URL.
  const [committedQuery, setCommittedQuery] = useState("");
  const [sort, setSort] = useState<SortMode>("score");
  const [kind, setKind] = useState<SearchKind>("product");
  const [items, setItems] = useState<SearchItem[]>([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [status, setStatus] = useState<
    "idle" | "loading" | "loadingMore" | "success" | "error"
  >("idle");
  const [errorMsg, setErrorMsg] = useState("");

  const abortRef = useRef<AbortController | null>(null);

  const fetchPage = useCallback(
    async (q: string, k: SearchKind, s: SortMode, cursor: string | null) => {
      if (q.length < MIN_LEN[k]) return;
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;

      setStatus(cursor ? "loadingMore" : "loading");
      setErrorMsg("");
      try {
        const params = new URLSearchParams({ q, kind: k });
        if (k === "product") {
          params.set("sort", s);
          params.set("limit", "50");
          if (cursor) params.set("cursor", cursor);
        }
        const res = await fetch(`/api/search?${params}`, { signal: ac.signal });
        const data = (await res.json().catch(() => null)) as
          | (SearchResponse & { error?: string })
          | null;
        if (!res.ok || !data) {
          throw new Error(data?.error ?? `Request failed (${res.status})`);
        }
        setItems((prev) => (cursor ? [...prev, ...data.items] : data.items));
        setTotal(data.total);
        setNextCursor(data.nextCursor);
        setStatus("success");
      } catch (e) {
        if ((e as Error).name === "AbortError") return;
        setStatus("error");
        setErrorMsg(e instanceof Error ? e.message : "Search failed");
      }
    },
    [],
  );

  // Sync from URL on mount and on back/forward navigation. The URL is the
  // source of truth for shareable searches: any change to ?q=, ?sort=, or
  // ?kind= here updates local state and triggers a fresh page-1 fetch.
  useEffect(() => {
    const urlQ = (searchParams.get("q") ?? "").trim();
    const urlSort = readSortFromUrl(searchParams.get("sort"));
    const urlKind = readKindFromUrl(searchParams.get("kind"));
    if (urlQ === committedQuery && urlSort === sort && urlKind === kind) return;
    setQuery(urlQ);
    setCommittedQuery(urlQ);
    setSort(urlSort);
    setKind(urlKind);
    if (urlQ.length >= MIN_LEN[urlKind]) {
      fetchPage(urlQ, urlKind, urlSort, null);
    } else {
      setItems([]);
      setTotal(0);
      setNextCursor(null);
      setStatus("idle");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  function updateUrl(q: string, k: SearchKind, s: SortMode, replace: boolean) {
    const params = new URLSearchParams(window.location.search);
    params.set("tab", "search");
    if (q) params.set("q", q);
    else params.delete("q");
    if (k === "id") {
      params.set("kind", "id");
      params.delete("sort");
    } else {
      params.delete("kind");
      params.set("sort", s);
    }
    const url = `${window.location.pathname}?${params}`;
    if (replace) router.replace(url, { scroll: false });
    else router.push(url, { scroll: false });
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = query.trim();
    if (trimmed.length < MIN_LEN[kind]) {
      setErrorMsg(
        kind === "id"
          ? "Please enter a CVE id"
          : "Please enter at least 2 characters",
      );
      setStatus("error");
      return;
    }
    setCommittedQuery(trimmed);
    updateUrl(trimmed, kind, sort, false);
    fetchPage(trimmed, kind, sort, null);
  }

  function handleSortChange(newSort: SortMode) {
    setSort(newSort);
    updateUrl(committedQuery, kind, newSort, true);
    if (committedQuery.length >= MIN_LEN[kind]) {
      fetchPage(committedQuery, kind, newSort, null);
    }
  }

  function handleKindChange(newKind: SearchKind) {
    setKind(newKind);
    updateUrl(committedQuery, newKind, sort, true);
    if (committedQuery.length >= MIN_LEN[newKind]) {
      fetchPage(committedQuery, newKind, sort, null);
    } else {
      setItems([]);
      setTotal(0);
      setNextCursor(null);
      setStatus("idle");
    }
  }

  function loadMore() {
    if (
      status === "success" &&
      nextCursor &&
      kind === "product" &&
      committedQuery.length >= MIN_LEN[kind]
    ) {
      fetchPage(committedQuery, kind, sort, nextCursor);
    }
  }

  return (
    <div>
      <form
        onSubmit={handleSubmit}
        className="flex flex-wrap items-center gap-2 mb-4"
      >
        <select
          value={kind}
          onChange={(e) => handleKindChange(e.target.value as SearchKind)}
          className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono text-zinc-300 cursor-pointer"
        >
          <option value="product">Product</option>
          <option value="id">CVE ID</option>
        </select>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={PLACEHOLDER[kind]}
          className="flex-1 min-w-0 bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
          autoFocus
        />
        <button type="submit" className="btn-primary">
          Search
        </button>
        {kind === "product" && (
          <select
            value={sort}
            onChange={(e) => handleSortChange(e.target.value as SortMode)}
            className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs font-mono text-zinc-300 cursor-pointer"
          >
            <option value="score">Severity (high → low)</option>
            <option value="date">Date (newest first)</option>
          </select>
        )}
      </form>

      {status === "idle" && (
        <div className="text-zinc-500 text-sm py-12 text-center">
          {kind === "id"
            ? "Enter a CVE id to look it up."
            : "Enter a product name to search CVEs."}
        </div>
      )}

      {status === "loading" && (
        <div className="flex items-center justify-center py-24 text-zinc-500 text-sm">
          Searching…
        </div>
      )}

      {status === "error" && (
        <div className="text-sm text-red-400 py-4">{errorMsg}</div>
      )}

      {(status === "success" || status === "loadingMore") && (
        <>
          <p className="text-sm text-zinc-400 mb-4">
            {total} {total === 1 ? "result" : "results"} for{" "}
            <span className="font-mono text-zinc-200">
              &quot;{committedQuery}&quot;
            </span>
          </p>
          {total === 0 ? (
            <div className="text-zinc-500 text-sm py-12 text-center">
              No matching CVEs.
            </div>
          ) : (
            <VirtuosoGrid
              useWindowScroll
              totalCount={items.length}
              endReached={loadMore}
              listClassName="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
              itemContent={(index) => {
                const item = items[index];
                if (!item || !item.vectorString) return null;
                const score = Number(item.baseScore);
                const vector = item.vectorString;
                return (
                  <GlyphCard
                    name={item.id}
                    nameMono
                    cveId={item.id}
                    subtitle={`${formatDateTime(item.published)}${item.version ? ` · CVSS ${item.version}` : ""}`}
                    description={item.description}
                    productName={item.product}
                    vector={vector}
                    score={score}
                    onLoadVector={() =>
                      loadVector({
                        name: item.id,
                        cve: item.id,
                        vector,
                        description: item.description,
                      })
                    }
                  />
                );
              }}
            />
          )}
          {status === "loadingMore" && (
            <div className="flex items-center justify-center py-6 text-zinc-500 text-xs">
              Loading more…
            </div>
          )}
        </>
      )}
    </div>
  );
}
