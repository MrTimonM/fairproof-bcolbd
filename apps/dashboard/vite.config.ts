import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],

  /*
   * circomlibjs is a Node library that has to run in the browser here, because
   * a credential signature must be byte-identical to the one the circuit's
   * EdDSA verifier checks. Its BLAKE-512 path pulls in `buffer`, `events`,
   * `util` and `stream`; Vite's default is to replace those with empty stubs
   * and warn, which produces a blank page at runtime rather than a build
   * failure. Pointing them at the real browser implementations is what makes
   * the page load, and `src/node-shims.ts` supplies the globals the same code
   * expects to find without importing.
   */
  resolve: {
    alias: {
      buffer: "buffer",
      events: "events",
      util: "util",
      stream: "readable-stream",
    },
  },
  define: {
    global: "globalThis",
  },
  optimizeDeps: {
    include: ["buffer", "events", "util", "readable-stream"],
    esbuildOptions: { define: { global: "globalThis" } },
  },

  server: {
    // Bind IPv4 explicitly. The default resolves "localhost" to ::1 on this
    // machine, so http://127.0.0.1:5173 was refused while http://localhost
    // worked - a confusing first impression for anyone given the numeric URL.
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
  },
  build: { outDir: "dist", sourcemap: true },
});
