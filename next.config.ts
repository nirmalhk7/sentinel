import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  // Pin tracing to this project so the standalone bundle is co-located with the
  // app (otherwise Next.js walks up to a parent lockfile and nests output deeply).
  outputFileTracingRoot: path.resolve(__dirname),
};

export default nextConfig;
