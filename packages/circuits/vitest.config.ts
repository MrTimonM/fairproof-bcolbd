import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  // Tests run against the TypeScript source, not packages/crypto/dist.
  // The published entry point is the build (so plain Node scripts and the
  // browser app can import it), but a stale dist silently testing old code
  // is a worse failure than a slightly slower test run.
  resolve: {
    alias: {
      "@fairproof/crypto": resolve(__dirname, "../crypto/src/index.ts"),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    // Circuit compilation and witness generation are slow.
    testTimeout: 180000,
    hookTimeout: 180000,
  },
});
