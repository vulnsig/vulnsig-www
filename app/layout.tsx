import type { Metadata } from "next";
import { Fira_Code, DM_Sans, Atomic_Age } from "next/font/google";
import "./globals.css";

const firaCode = Fira_Code({
  variable: "--font-mono",
  subsets: ["latin"],
});

const dmSans = DM_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
});

const atomicAge = Atomic_Age({
  weight: "400",
  variable: "--font-display",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "VulnSig",
  description: "VulnSig encodes CVSS metrics into an expressive visual glyph.",
  openGraph: {
    title: "VulnSig",
    description:
      "VulnSig encodes CVSS metrics into an expressive visual glyph.",
    url: "https://vulnsig.io",
    siteName: "VulnSig",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${firaCode.variable} ${dmSans.variable} ${atomicAge.variable} antialiased bg-zinc-950 text-zinc-100 font-sans`}
      >
        {children}
      </body>
    </html>
  );
}
