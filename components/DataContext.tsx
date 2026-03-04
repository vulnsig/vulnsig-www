"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  type ReactNode,
} from "react";
import cveDataStatic from "@/data/cve-recent.json";
import kevDataStatic from "@/data/kev-recent.json";

export interface CveEntry {
  id: string;
  published: string;
  description: string;
  cvss: { version: string; vectorString: string; baseScore: number };
}

export interface CveDataset {
  generatedAt: string;
  windowStart: string;
  windowEnd: string;
  cves: CveEntry[];
}

interface DataContextValue {
  cveData: CveDataset;
  kevData: CveDataset;
}

const DataContext = createContext<DataContextValue | null>(null);

// Set NEXT_PUBLIC_CVE_DATA_URL / NEXT_PUBLIC_KEV_DATA_URL to point at S3
// (or any HTTP source) when available. Without them the bundled JSON is used
// as initial state and no refresh fetches are made.
const CVE_DATA_URL = process.env.NEXT_PUBLIC_CVE_DATA_URL ?? null;
const KEV_DATA_URL = process.env.NEXT_PUBLIC_KEV_DATA_URL ?? null;
const REFRESH_MS = 60 * 60 * 1000; // 1 hour

async function fetchDataset(url: string): Promise<CveDataset> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<CveDataset>;
}

export function DataProvider({ children }: { children: ReactNode }) {
  const [cveData, setCveData] = useState<CveDataset>(
    cveDataStatic as CveDataset,
  );
  const [kevData, setKevData] = useState<CveDataset>(
    kevDataStatic as CveDataset,
  );

  useEffect(() => {
    if (!CVE_DATA_URL && !KEV_DATA_URL) return;

    let cancelled = false;

    async function refresh() {
      if (CVE_DATA_URL) {
        try {
          const data = await fetchDataset(CVE_DATA_URL);
          if (!cancelled) setCveData(data);
        } catch (e) {
          console.warn("[DataContext] CVE data refresh failed:", e);
        }
      }
      if (KEV_DATA_URL) {
        try {
          const data = await fetchDataset(KEV_DATA_URL);
          if (!cancelled) setKevData(data);
        } catch (e) {
          console.warn("[DataContext] KEV data refresh failed:", e);
        }
      }
    }

    refresh();
    const id = setInterval(refresh, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <DataContext.Provider value={{ cveData, kevData }}>
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error("useData must be used within DataProvider");
  return ctx;
}
