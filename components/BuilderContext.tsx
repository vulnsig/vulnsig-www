"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
  type ReactNode,
} from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { VULNERABILITIES, type Vulnerability } from "@/data/vulnerabilities";
import { useData, type CveDataset } from "./DataContext";

function findVulnByCve(
  cveId: string,
  fallbackVector: string,
  cveData: CveDataset,
  kevData: CveDataset,
): Vulnerability {
  const fromGallery = VULNERABILITIES.find((v) => v.cve === cveId);
  if (fromGallery) return fromGallery;

  const fromRecent = cveData.cves.find((v) => v.id === cveId);
  if (fromRecent)
    return {
      name: cveId,
      cve: cveId,
      vector: fromRecent.cvss.vectorString,
      description: fromRecent.description,
    };

  const fromKev = kevData.cves.find((v) => v.id === cveId);
  if (fromKev)
    return {
      name: cveId,
      cve: cveId,
      vector: fromKev.cvss.vectorString,
      description: fromKev.description,
    };

  return { name: cveId, cve: cveId, vector: fallbackVector, description: "" };
}

interface BuilderContextValue {
  vector: string;
  setVector: (v: string, push?: boolean) => void;
  selectedVuln: Vulnerability | null;
  expanded: boolean;
  setExpanded: (e: boolean) => void;
  loadVector: (vuln: Vulnerability) => void;
  builderRef: React.RefObject<HTMLDivElement | null>;
  heroRef: React.RefObject<HTMLDivElement | null>;
  activeTab: string;
  setActiveTab: (t: string) => void;
  navigateToPackageSection: (sectionId: string) => void;
}

const BuilderContext = createContext<BuilderContextValue | null>(null);

export function BuilderProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { cveData, kevData } = useData();

  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(
    () => VULNERABILITIES[Math.floor(Math.random() * VULNERABILITIES.length)],
  );
  const [vector, setVectorRaw] = useState(() => selectedVuln?.vector ?? "");
  const [expanded, setExpanded] = useState(false);

  const setVector = useCallback(
    (v: string, push = false) => {
      setSelectedVuln(null);
      setVectorRaw(v);
      const params = new URLSearchParams(window.location.search);
      if (v) {
        params.set("vector", v);
        params.delete("cve");
        if (push) {
          router.push(`${window.location.pathname}?${params}`, {
            scroll: false,
          });
        } else {
          history.replaceState(
            null,
            "",
            `${window.location.pathname}?${params}`,
          );
        }
      } else {
        params.delete("vector");
        params.delete("cve");
        const search = params.toString();
        history.replaceState(
          null,
          "",
          search
            ? `${window.location.pathname}?${search}`
            : window.location.pathname,
        );
      }
    },
    [router],
  );
  const [activeTab, setActiveTabState] = useState(
    () => searchParams.get("tab") ?? "cves",
  );

  const setActiveTab = useCallback(
    (tab: string) => {
      setActiveTabState(tab);
      const params = new URLSearchParams(window.location.search);
      params.set("tab", tab);
      router.push(`${window.location.pathname}?${params}`, { scroll: false });
    },
    [router],
  );
  const builderRef = useRef<HTMLDivElement | null>(null);
  const heroRef = useRef<HTMLDivElement | null>(null);

  // Sync tab from URL on back/forward
  useEffect(() => {
    const urlTab = searchParams.get("tab") ?? "cves";
    if (urlTab !== activeTab) setActiveTabState(urlTab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  // Sync vector state from URL — handles initial load, back, and forward.
  // Skip when the vector already matches to avoid a redundant re-render
  // after loadVector / setVector update state and the URL simultaneously.
  useEffect(() => {
    const urlVector = searchParams.get("vector");
    const urlCve = searchParams.get("cve");
    if (!urlVector || urlVector === vector) return;
    const vuln = urlCve
      ? findVulnByCve(urlCve, urlVector, cveData, kevData)
      : null;
    setVectorRaw(vuln?.vector ?? urlVector);
    setSelectedVuln(vuln);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, cveData, kevData]);

  const navigateToPackageSection = useCallback(
    (sectionId: string) => {
      setActiveTab("tools");
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) {
          const y = el.getBoundingClientRect().top + window.scrollY - 80;
          window.scrollTo({ top: y, behavior: "smooth" });
          // Restart animation even if triggered repeatedly
          el.classList.remove("section-highlight");
          void el.offsetWidth;
          el.classList.add("section-highlight");
          setTimeout(() => el.classList.remove("section-highlight"), 1400);
        }
      }, 50);
    },
    [setActiveTab],
  );

  const loadVector = useCallback(
    (vuln: Vulnerability) => {
      setSelectedVuln(vuln);
      setVectorRaw(vuln.vector);
      setExpanded(true);
      // Use the Next.js router so back/forward updates useSearchParams correctly
      const params = new URLSearchParams(window.location.search);
      params.set("vector", vuln.vector);
      if (vuln.cve) params.set("cve", vuln.cve);
      else params.delete("cve");
      router.push(`${window.location.pathname}?${params}`, { scroll: false });
      // Scroll to the hero glyph
      setTimeout(() => {
        if (heroRef.current) {
          const y =
            heroRef.current.getBoundingClientRect().top + window.scrollY - 64;
          window.scrollTo({ top: y, behavior: "smooth" });
        }
      }, 50);
    },
    [router],
  );

  return (
    <BuilderContext.Provider
      value={{
        vector,
        setVector,
        selectedVuln,
        expanded,
        setExpanded,
        loadVector,
        builderRef,
        heroRef,
        activeTab,
        setActiveTab,
        navigateToPackageSection,
      }}
    >
      {children}
    </BuilderContext.Provider>
  );
}

export function useBuilder() {
  const ctx = useContext(BuilderContext);
  if (!ctx) throw new Error("useBuilder must be used within BuilderProvider");
  return ctx;
}
