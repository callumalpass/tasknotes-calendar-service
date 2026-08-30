import type { D1Migration } from "@cloudflare/vitest-pool-workers";
import { env } from "cloudflare:workers";
import { applyD1Migrations } from "cloudflare:test";
import { beforeEach } from "vitest";

import type { Env } from "../../src/env";

interface TestEnv extends Env {
  TEST_MIGRATIONS: D1Migration[];
}

beforeEach(async () => {
  const testEnv = env as unknown as TestEnv;
  await applyD1Migrations(testEnv.DB, testEnv.TEST_MIGRATIONS);
});
