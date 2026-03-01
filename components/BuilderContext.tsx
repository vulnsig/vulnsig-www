"use client";

import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from "react";

interface BuilderContextValue {
  vector: string;
  setVector: (v: string) => void;
  expanded: boolean;
  setExpanded: (e: boolean) => void;
  loadVector: (v: string) => void;
  builderRef: React.RefObject<HTMLDivElement | null>;
  heroRef: React.RefObject<HTMLDivElement | null>;
}

const BuilderContext = createContext<BuilderContextValue | null>(null);

export function BuilderProvider({ children }: { children: ReactNode }) {
  const [vector, setVector] = useState(
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  );
  const [expanded, setExpanded] = useState(false);
  const builderRef = useRef<HTMLDivElement | null>(null);
  const heroRef = useRef<HTMLDivElement | null>(null);

  const loadVector = useCallback(
    (v: string) => {
      setVector(v);
      setExpanded(true);
      // Scroll to the hero glyph
      setTimeout(() => {
        heroRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 50);
    },
    []
  );

  return (
    <BuilderContext.Provider
      value={{ vector, setVector, expanded, setExpanded, loadVector, builderRef, heroRef }}
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
