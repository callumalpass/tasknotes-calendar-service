import { describe, expect, it, vi } from "vitest";
import { withLabCors } from "../../src/http/lab-cors";

const origin = "https://lab.tasknotes-app.pages.dev";
const service = "https://tasknotes-calendar-lab.callumalpass.workers.dev";
function request(headers: Record<string, string> = {}, method = "OPTIONS", path = "/v1/calendars") {
  return new Request(`${service}${path}`, {
    method,
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "authorization",
      ...headers,
    },
  });
}
describe("single LAB browser CORS boundary", () => {
  it("allows reviewed preflights without authenticating or accessing D1", async () => {
    const handle = vi.fn();
    const response = await withLabCors(request(), "lab", handle);
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(handle).not.toHaveBeenCalled();
  });
  it.each(["https://evil.example", "null", `${origin}.evil.example`, `${origin}/`])(
    "rejects untrusted origin %s",
    async (Origin) => {
      const handle = vi.fn();
      const response = await withLabCors(request({ Origin }), "lab", handle);
      expect(response.status).toBe(403);
      expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
      expect(handle).not.toHaveBeenCalled();
    },
  );
  it.each(["local", "staging", "production"])(
    "cannot enable browser access in %s",
    async (environment) => {
      expect((await withLabCors(request(), environment, vi.fn())).status).toBe(403);
    },
  );
  it.each([
    { "Access-Control-Request-Method": "PUT" },
    { "Access-Control-Request-Headers": "authorization, x-custom" },
    { "Access-Control-Request-Headers": "authorization," },
  ])("rejects unsupported preflights", async (headers) => {
    expect((await withLabCors(request(headers), "lab", vi.fn())).status).toBe(403);
  });
  it("does not expose callbacks or unknown routes", async () => {
    for (const path of ["/oauth/google/callback", "/health/live", "/v1/nope"]) {
      expect((await withLabCors(request({}, "OPTIONS", path), "lab", vi.fn())).status).toBe(403);
    }
  });
  it("adds CORS to authenticated failures without weakening authentication", async () => {
    const handle = vi.fn(() =>
      Promise.resolve(
        new Response(null, { status: 401, headers: { "Cache-Control": "private, no-store" } }),
      ),
    );
    const response = await withLabCors(request({}, "GET"), "lab", handle);
    expect(response.status).toBe(401);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(origin);
    expect(handle).toHaveBeenCalledOnce();
  });
  it("preserves non-browser clients", async () => {
    const handle = vi.fn(() => Promise.resolve(new Response("ok")));
    const response = await withLabCors(new Request(`${service}/health/live`), "lab", handle);
    expect(await response.text()).toBe("ok");
    expect(response.headers.has("Access-Control-Allow-Origin")).toBe(false);
  });
});
