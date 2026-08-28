import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["better-sqlite3", "tesseract.js", "sharp"],
  output: "standalone",
};

export default nextConfig;
