import { routes } from "../contracts/routes";
import { errorResponse } from "./responses";

const appOrigin = "https://lab.tasknotes-app.pages.dev";
const serviceOrigin = "https://tasknotes-calendar-lab.callumalpass.workers.dev";

/** A single reviewed browser consumer, not an arbitrary-origin proxy. */
export async function withLabCors(
  request: Request,
  environment: string,
  handle: () => Promise<Response>,
): Promise<Response> {
  const origin = request.headers.get("Origin");
  if (!origin) return handle();
  if (
    environment !== "lab" ||
    new URL(request.url).origin !== serviceOrigin ||
    origin !== appOrigin
  )
    return errorResponse("permission_denied");

  const path = new URL(request.url).pathname;
  const method =
    request.method === "OPTIONS"
      ? request.headers.get("Access-Control-Request-Method")
      : request.method;
  const matched = routes.some(
    (route) =>
      route.path.startsWith("/v1/") &&
      route.method === method &&
      new RegExp(`^${route.path.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(path),
  );
  if (!matched || method === null) return errorResponse("permission_denied");

  let response: Response;
  if (request.method === "OPTIONS") {
    const requested = request.headers.get("Access-Control-Request-Headers");
    const headers = requested?.split(",").map((value) => value.trim().toLowerCase()) ?? [];
    if (headers.some((value) => !["authorization", "content-type"].includes(value))) {
      return errorResponse("permission_denied");
    }
    response = new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Methods": method,
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Cache-Control": "private, no-store",
      },
    });
  } else response = await handle();
  const result = new Response(response.body, response);
  result.headers.set("Access-Control-Allow-Origin", appOrigin);
  result.headers.append("Vary", "Origin");
  if (request.method === "OPTIONS") {
    result.headers.append("Vary", "Access-Control-Request-Method, Access-Control-Request-Headers");
  }
  return result;
}
