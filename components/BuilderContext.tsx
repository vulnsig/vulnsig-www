"use client";

import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from "react";

interface BuilderContextValue {
  vector: string;
  setVector: (v: string) => void;
  expanded: boolean;
  setExpanded: (e: boolean) => void;
  loadVector: (v: string) => void;
  builderRef: React.RefObject<HTMLDivElement | null>;
}

const BuilderContext = createContext<BuilderContextValue | null>(null);

export function BuilderProvider({ children }: { children: ReactNode }) {
  const [vector, setVector] = useState(
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
  );
  const [expanded, setExpanded] = useState(false);
  const builderRef = useRef<HTMLDivElement | null>(null);

  const loadVector = useCallback(
    (v: string) => {
      setVector(v);
      setExpanded(true);
      // Scroll to builder bar
      setTimeout(() => {
        builderRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 50);
    },
    []
  );

  return (
    <BuilderContext.Provider
      value={{ vector, setVector, expanded, setExpanded, loadVector, builderRef }}
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
