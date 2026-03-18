"use client";

import { useState } from "react";
import { ShareDialog } from "./ShareDialog";

interface ShareButtonProps {
  cveId: string;
  vector: string;
  score: number;
  description: string;
  productName?: string;
}

export function ShareButton({
  cveId,
  vector,
  score,
  description,
  productName,
}: ShareButtonProps) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        aria-label={`Share ${cveId}`}
        title={`Share ${cveId}`}
        className="text-zinc-600 hover:text-zinc-300 transition-colors cursor-pointer"
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
          <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8" />
          <polyline points="16 6 12 2 8 6" />
          <line x1="12" y1="2" x2="12" y2="15" />
        </svg>
      </button>
      <ShareDialog
        open={open}
        onClose={() => setOpen(false)}
        cveId={cveId}
        vector={vector}
        score={score}
        description={description}
        productName={productName}
      />
    </>
  );
}
