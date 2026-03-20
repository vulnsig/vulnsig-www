import { Masthead } from "@/components/Masthead";
import { Footer } from "@/components/Footer";

const API_BASE = process.env.NEXT_PUBLIC_VULNSIG_API_URL ?? "";

interface PageProps {
  searchParams: Promise<Record<string, string | undefined>>;
}

async function unsubscribeToken(token: string): Promise<"success" | "invalid"> {
  if (!API_BASE) return "invalid";
  try {
    const res = await fetch(
      `${API_BASE}/unsubscribe?token=${encodeURIComponent(token)}`,
    );
    return res.ok ? "success" : "invalid";
  } catch {
    return "invalid";
  }
}

export default async function UnsubscribePage({ searchParams }: PageProps) {
  const { token } = await searchParams;
  const status = token ? await unsubscribeToken(token) : "invalid";

  return (
    <div className="min-h-screen flex flex-col">
      <Masthead />
      <main className="flex-1 flex items-center justify-center px-4 pt-16">
        <div className="max-w-md text-center">
          {status === "success" ? (
            <>
              <h1 className="text-2xl font-semibold mb-4">
                You&apos;ve been unsubscribed
              </h1>
              <p className="text-sm text-zinc-400">
                You will no longer receive VulnSig Digest emails.
              </p>
            </>
          ) : (
            <>
              <h1 className="text-2xl font-semibold mb-4">Invalid link</h1>
              <p className="text-sm text-zinc-400">
                This unsubscribe link is not valid. Please check the link and
                try again.
              </p>
            </>
          )}
        </div>
      </main>
      <Footer />
    </div>
  );
}
