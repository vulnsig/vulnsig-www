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
import cveProductStatic from "@/data/cve-recent-product.json";
import kevProductStatic from "@/data/kev-recent-product.json";

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

export interface ProductEntry {
  product: string;
  added: string;
}

export type ProductMap = Record<string, ProductEntry>;

interface DataContextValue {
  cveData: CveDataset;
  kevData: CveDataset;
  cveProductMap: ProductMap;
  kevProductMap: ProductMap;
}

const DataContext = createContext<DataContextValue | null>(null);

// Set NEXT_PUBLIC_CVE_DATA_URL / NEXT_PUBLIC_KEV_DATA_URL to point at S3
// (or any HTTP source) when available. Without them the bundled JSON is used
// as initial state and no refresh fetches are made.
const CVE_DATA_URL = process.env.NEXT_PUBLIC_CVE_DATA_URL ?? null;
const KEV_DATA_URL = process.env.NEXT_PUBLIC_KEV_DATA_URL ?? null;
const REFRESH_MS = 60 * 60 * 1000; // 1 hour

/** Derive the product-map URL by inserting '-product' before '.json'. */
function productUrl(url: string): string {
  return url.replace(/\.json$/, "-product.json");
}

const CVE_PRODUCT_URL = CVE_DATA_URL ? productUrl(CVE_DATA_URL) : null;
const KEV_PRODUCT_URL = KEV_DATA_URL ? productUrl(KEV_DATA_URL) : null;

async function fetchDataset(url: string): Promise<CveDataset> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<CveDataset>;
}

async function fetchProductMap(url: string): Promise<ProductMap> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<ProductMap>;
}

export function DataProvider({ children }: { children: ReactNode }) {
  const [cveData, setCveData] = useState<CveDataset>(
    cveDataStatic as CveDataset,
  );
  const [kevData, setKevData] = useState<CveDataset>(
    kevDataStatic as CveDataset,
  );
  const [cveProductMap, setCveProductMap] = useState<ProductMap>(
    cveProductStatic as ProductMap,
  );
  const [kevProductMap, setKevProductMap] = useState<ProductMap>(
    kevProductStatic as ProductMap,
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
      if (CVE_PRODUCT_URL) {
        try {
          const data = await fetchProductMap(CVE_PRODUCT_URL);
          if (!cancelled) setCveProductMap(data);
        } catch (e) {
          console.warn("[DataContext] CVE product map refresh failed:", e);
        }
      }
      if (KEV_PRODUCT_URL) {
        try {
          const data = await fetchProductMap(KEV_PRODUCT_URL);
          if (!cancelled) setKevProductMap(data);
        } catch (e) {
          console.warn("[DataContext] KEV product map refresh failed:", e);
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
    <DataContext.Provider
      value={{ cveData, kevData, cveProductMap, kevProductMap }}
    >
      {children}
    </DataContext.Provider>
  );
}

export function useData() {
  const ctx = useContext(DataContext);
  if (!ctx) throw new Error("useData must be used within DataProvider");
  return ctx;
}
