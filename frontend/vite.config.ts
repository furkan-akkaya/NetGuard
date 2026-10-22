import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The production bundle is served by the NetGuard API (`netguard serve`) from the
// Python package, so it is built straight into src/netguard/web/static.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../src/netguard/web/static",
    emptyOutDir: true,
    sourcemap: false,
    // No inline scripts or styles: the dashboard runs under script-src 'self'.
    assetsInlineLimit: 0,
  },
  server: {
    // `pnpm dev`: proxy the API to a locally running `netguard serve`.
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
