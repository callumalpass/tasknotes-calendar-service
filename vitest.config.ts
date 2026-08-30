import fs from "node:fs/promises";
import path from "node:path";

import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import ts from "typescript";
import { defineConfig } from "vitest/config";

const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
const fakeGoogleWorker = ts.transpileModule(
  await fs.readFile(path.join(import.meta.dirname, "test/support/fake-google-worker.ts"), "utf8"),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.jsonc",
      },
      miniflare: {
        bindings: {
          TEST_MIGRATIONS: migrations,
          GOOGLE_CLIENT_SECRET: "test-only-fake-google-secret",
          OAUTH_TRANSACTION_KEK_V1: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
          TOKEN_KEK_V1: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
          SESSION_PEPPER: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
          IDENTITY_FENCE_KEY: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
          CURSOR_KEY: "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
          EVENT_ID_KEY_V1: "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
        },
        outboundService: "fake-google",
        serviceBindings: {
          FAKE_GOOGLE: "fake-google",
        },
        workers: [
          {
            name: "fake-google",
            compatibilityDate: "2026-08-22",
            modules: [
              {
                type: "ESModule",
                path: "fake-google-worker.js",
                contents: fakeGoogleWorker,
              },
            ],
          },
        ],
      },
    }),
  ],
  test: {
    coverage: {
      provider: "istanbul",
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
