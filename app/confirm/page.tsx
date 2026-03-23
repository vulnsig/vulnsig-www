import Link from "next/link";
import { Masthead } from "@/components/Masthead";
import { Footer } from "@/components/Footer";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";

interface PageProps {
  searchParams: Promise<Record<string, string | undefined>>;
}

async function confirmToken(token: string): Promise<"success" | "invalid"> {
  if (!API_BASE) return "invalid";
  try {
    const res = await fetch(
      `${API_BASE}/confirm?token=${encodeURIComponent(token)}`,
    );
    return res.ok ? "success" : "invalid";
  } catch {
    return "invalid";
  }
}

export default async function ConfirmPage({ searchParams }: PageProps) {
  const { token } = await searchParams;
  const status = token ? await confirmToken(token) : undefined;

  return (
    <div className="min-h-screen flex flex-col">
      <Masthead />
      <main className="flex-1 flex items-center justify-center px-4 pt-16">
        <div className="max-w-md text-center">
          {status === "success" ? (
            <>
              <h1 className="text-2xl font-semibold mb-4">
                You are subscribed!
              </h1>
              <p className="text-sm text-zinc-400">
                Your email has been confirmed. You will receive the next VulnSig
                Digest.
              </p>
            </>
          ) : status === "invalid" ? (
            <>
              <h1 className="text-2xl font-semibold mb-4">
                Invalid or expired link
              </h1>
              <p className="text-sm text-zinc-400">
                This confirmation link is no longer valid. Please{" "}
                <Link
                  href="/?tab=subscribe"
                  className="text-zinc-300 hover:text-zinc-100 underline underline-offset-2 decoration-zinc-600 hover:decoration-zinc-400 transition-colors"
                >
                  subscribe again
                </Link>
                .
              </p>
            </>
          ) : (
            <>
              <h1 className="text-2xl font-semibold mb-4">Confirmation</h1>
              <p className="text-sm text-zinc-400">
                Check your email for a confirmation link.
              </p>
            </>
          )}
        </div>
      </main>
      <Footer />
    </div>
  );
}
