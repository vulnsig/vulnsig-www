"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { VULNERABILITIES, type Vulnerability } from "@/data/vulnerabilities";

interface BuilderContextValue {
  vector: string;
  setVector: (v: string) => void;
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
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(
    () => VULNERABILITIES[Math.floor(Math.random() * VULNERABILITIES.length)],
  );
  const [vector, setVectorRaw] = useState(() => selectedVuln?.vector ?? "");
  const [expanded, setExpanded] = useState(false);

  const setVector = useCallback((v: string) => {
    setSelectedVuln(null);
    setVectorRaw(v);
  }, []);
  const [activeTab, setActiveTab] = useState("gallery");
  const builderRef = useRef<HTMLDivElement | null>(null);
  const heroRef = useRef<HTMLDivElement | null>(null);

  const navigateToPackageSection = useCallback((sectionId: string) => {
    setActiveTab("packages");
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
  }, []);

  const loadVector = useCallback((vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setVectorRaw(vuln.vector);
    setExpanded(true);
    // Scroll to the hero glyph
    setTimeout(() => {
      if (heroRef.current) {
        const y =
          heroRef.current.getBoundingClientRect().top + window.scrollY - 64;
        window.scrollTo({ top: y, behavior: "smooth" });
      }
    }, 50);
  }, []);

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
