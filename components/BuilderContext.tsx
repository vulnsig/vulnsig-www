"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { VULNERABILITIES } from "@/data/vulnerabilities";

interface BuilderContextValue {
  vector: string;
  setVector: (v: string) => void;
  expanded: boolean;
  setExpanded: (e: boolean) => void;
  loadVector: (v: string) => void;
  builderRef: React.RefObject<HTMLDivElement | null>;
  heroRef: React.RefObject<HTMLDivElement | null>;
  activeTab: string;
  setActiveTab: (t: string) => void;
  navigateToPackageSection: (sectionId: string) => void;
}

const BuilderContext = createContext<BuilderContextValue | null>(null);

export function BuilderProvider({ children }: { children: ReactNode }) {
  const [vector, setVector] = useState(
    () =>
      VULNERABILITIES[Math.floor(Math.random() * VULNERABILITIES.length)]
        .vector,
  );
  const [expanded, setExpanded] = useState(false);
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
      }
    }, 50);
  }, []);

  const loadVector = useCallback((v: string) => {
    setVector(v);
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
