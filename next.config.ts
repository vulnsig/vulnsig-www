import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverRuntimeConfig: {
    apiSecret: process.env.API_SECRET ?? "",
  },
};

export default nextConfig;
