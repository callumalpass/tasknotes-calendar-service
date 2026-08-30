import type { ApiError } from "../contracts/common";

export const JSON_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
} as const;

const ERROR_DEFINITIONS = {
  invalid_request: { status: 400, message: "Request is invalid." },
  unsupported_media_type: { status: 415, message: "Content type must be application/json." },
  payload_too_large: { status: 413, message: "Request body is too large." },
  authentication_required: { status: 401, message: "Authentication is required." },
  permission_denied: { status: 403, message: "Request is not permitted." },
  resource_not_found: { status: 404, message: "Resource not found." },
  conflict: { status: 409, message: "Request conflicts with current state." },
  rate_limited: { status: 429, message: "Too many requests." },
  dependency_unavailable: { status: 503, message: "Service is temporarily unavailable." },
  internal_error: { status: 500, message: "An internal error occurred." },
} as const satisfies Record<ApiError["code"], { status: number; message: string }>;

export type ErrorCode = keyof typeof ERROR_DEFINITIONS;

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export function noContentResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function errorResponse(code: ErrorCode, retryAfterSeconds?: number): Response {
  const definition = ERROR_DEFINITIONS[code];
  const headers = new Headers(JSON_HEADERS);
  if (
    retryAfterSeconds !== undefined &&
    (code === "rate_limited" || code === "dependency_unavailable")
  ) {
    headers.set("retry-after", String(Math.min(300, Math.max(1, Math.trunc(retryAfterSeconds)))));
  }
  return new Response(JSON.stringify({ code, message: definition.message }), {
    status: definition.status,
    headers,
  });
}

export class ContractError extends Error {
  readonly code: ErrorCode;
  readonly retryAfterSeconds: number | undefined;

  constructor(code: ErrorCode, retryAfterSeconds?: number) {
    super(ERROR_DEFINITIONS[code].message);
    this.name = "ContractError";
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
