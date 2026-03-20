"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { SocialIcon } from "react-social-icons";
import { VulnSig } from "vulnsig-react";
import {
  getShareSentence,
  buildLandingUrl,
  buildShareText,
  buildPlatformUrls,
  openShareWindow,
} from "@/lib/shareUtils";

interface ShareDialogProps {
  open: boolean;
  onClose: () => void;
  cveId: string;
  vector: string;
  score: number;
  description: string;
  productName?: string;
}

export function ShareDialog({
  open,
  onClose,
  cveId,
  vector,
  score,
  description,
  productName,
}: ShareDialogProps) {
  const [copied, setCopied] = useState(false);
  const overlayRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const sentence = getShareSentence(description, productName);
  const landingUrl = buildLandingUrl(cveId);
  const shareText = buildShareText(cveId, score, sentence);
  const urls = buildPlatformUrls(shareText, landingUrl, cveId, sentence);

  function handleOverlayClick(e: React.MouseEvent<HTMLDivElement>) {
    if (e.target === overlayRef.current) onClose();
  }

  async function handleCopyLink() {
    await navigator.clipboard.writeText(landingUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const btnClass =
    "p-2 rounded bg-zinc-800 hover:bg-zinc-700 transition-colors cursor-pointer";

  return createPortal(
    <div
      ref={overlayRef}
      className="fixed inset-0 bg-black/60 z-[200] flex items-center justify-center p-4"
      onClick={handleOverlayClick}
    >
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 max-w-md w-full">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <h2 className="text-sm font-semibold text-zinc-200">Share</h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
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
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Preview */}
        <div className="flex items-start gap-4">
          <div className="flex-none">
            <VulnSig vector={vector} size={64} score={score} />
          </div>
          <div className="min-w-0">
            <p className="font-mono text-sm text-zinc-400">{cveId}</p>
            <p className="text-sm text-zinc-300 mt-2 leading-relaxed break-words">
              {sentence}
            </p>
          </div>
        </div>

        {/* Platform buttons */}
        <div className="flex flex-wrap gap-2 mt-6">
          <button
            className={btnClass}
            title="X / Twitter"
            onClick={() => openShareWindow(urls.twitter, 550, 420)}
          >
            <SocialIcon
              network="x"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="LinkedIn"
            onClick={() => openShareWindow(urls.linkedin, 600, 600)}
          >
            <SocialIcon
              network="linkedin"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="Bluesky"
            onClick={() => openShareWindow(urls.bluesky, 600, 500)}
          >
            <SocialIcon
              network="bsky.app"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="Threads"
            onClick={() => openShareWindow(urls.threads, 600, 500)}
          >
            <SocialIcon
              network="threads"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="Reddit"
            onClick={() => openShareWindow(urls.reddit, 600, 500)}
          >
            <SocialIcon
              network="reddit"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="Email"
            onClick={() => {
              window.location.href = urls.email;
            }}
          >
            <SocialIcon
              network="email"
              style={{ width: 28, height: 28, overflow: "visible" }}
            />
          </button>
          <button
            className={btnClass}
            title="Copy Link"
            onClick={handleCopyLink}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="22"
              height="22"
              viewBox="0 0 24 24"
              className="m-[3px] text-zinc-400"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {copied ? (
                <polyline points="20 6 9 17 4 12" />
              ) : (
                <>
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                </>
              )}
            </svg>
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
}
