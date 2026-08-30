import type { Env } from "./env";

const JSON_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
} as const;

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: JSON_HEADERS });
}

export function createWorker(): ExportedHandler<Env> {
  return {
    async fetch(request, env): Promise<Response> {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/health/live") {
        return json({ status: "ok" });
      }

      if (request.method === "GET" && url.pathname === "/health/ready") {
        try {
          await env.DB.prepare("SELECT 1 AS ready").first();
          return json({ status: "ready" });
        } catch {
          return json({ code: "dependency_unavailable", message: "Service is not ready." }, 503);
        }
      }

      return json({ code: "resource_not_found", message: "Resource not found." }, 404);
    },
  };
}

export default createWorker();
