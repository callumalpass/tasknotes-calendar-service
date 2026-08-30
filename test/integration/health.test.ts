import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

import type { Env } from "../../src/env";

const testEnv = env as unknown as Env;

describe("health endpoints", () => {
  it("reports liveness without consulting D1", async () => {
    const response = await exports.default.fetch(new Request("https://calendar.test/health/live"));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({ status: "ok" });
  });

  it("reports readiness when D1 is available", async () => {
    await expect(testEnv.DB.prepare("SELECT 1 AS ready").first()).resolves.toEqual({ ready: 1 });

    const response = await exports.default.fetch(new Request("https://calendar.test/health/ready"));

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: "ready" });
  });

  it("returns a stable private not-found response", async () => {
    const response = await exports.default.fetch(new Request("https://calendar.test/not-found"));

    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
    await expect(response.json()).resolves.toEqual({
      code: "resource_not_found",
      message: "Resource not found.",
    });
  });
});
