import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Static export — the FastAPI server (see repo worklog contract) serves dashboard/out at "/"
  // alongside the /api routes. No server features are used by the dashboard.
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
