import path from "node:path";
import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The demo is static files: no server, no API route, nothing to keep running.
  // `next build` emits a directory any CDN can host.
  output: "export",
  reactStrictMode: true,
  // The repo root has its own package-lock.json for the Phase 1 probe, so
  // Turbopack sees two lockfiles and guesses wrong about which tree it is
  // building. This is the demo app; its root is this directory.
  turbopack: { root: path.dirname(fileURLToPath(import.meta.url)) },
};

export default nextConfig;
