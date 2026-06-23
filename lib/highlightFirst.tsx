import type { ReactNode } from "react";
import Link from "next/link";

/** Highlight the first occurrence of `term` in `text`, case-insensitive,
 *  and link it to the search tab for that product. */
export function highlightFirst(text: string, term: string): ReactNode {
  const idx = text.toLowerCase().indexOf(term.toLowerCase());
  if (idx === -1) return text;
  const before = text.slice(0, idx);
  const match = text.slice(idx, idx + term.length);
  const after = text.slice(idx + term.length);
  const href = `/?tab=search&q=${encodeURIComponent(term)}&sort=date`;
  return (
    <>
      {before}
      <Link
        href={href}
        title={`Search CVEs for "${term}"`}
        className="text-zinc-200 font-medium hover:text-white transition-colors"
      >
        {match}
      </Link>
      {after}
    </>
  );
}
