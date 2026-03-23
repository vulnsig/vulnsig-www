import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  env: {
    // Inlined at build time so the value is available in SSR Lambda at runtime
    // without needing Amplify to inject env vars into the Lambda environment.
    // Safe to inline here because this var is only used in server-side route handlers.
    API_SECRET: process.env.API_SECRET ?? "",
  },
};

export default nextConfig;
