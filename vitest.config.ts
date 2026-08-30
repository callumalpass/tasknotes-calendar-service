import path from "node:path";

import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc",
      },
      miniflare: {
        bindings: { TEST_MIGRATIONS: migrations },
      },
    }),
  ],
  test: {
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      thresholds: {
        branches: 85,
        functions: 90,
        lines: 90,
        statements: 90,
      },
    },
    setupFiles: ["./test/support/apply-migrations.ts"],
    testTimeout: 10_000,
  },
});
