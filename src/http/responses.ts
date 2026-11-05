import type { OAuthCallbackResult } from "../auth/oauth-transactions";
import type { ApiError } from "../contracts/common";

export const JSON_HEADERS = {
  "cache-control": "private, no-store",
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
  sync_reset_required: { status: 410, message: "Calendar sync must be restarted." },
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
      "cache-control": "private, no-store",
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

export function linkingResponse(result: OAuthCallbackResult): Response {
  const nonce = crypto.randomUUID();
  const title =
    result.status === "failed"
      ? "Authorization not completed"
      : result.confirmationCode === undefined
        ? "Calendar connected"
        : "Confirm your sign-in";
  const message =
    result.status === "failed"
      ? "Return to TaskNotes and start again."
      : result.confirmationCode === undefined
        ? "You can close this page and return to TaskNotes."
        : "Enter this code only in the TaskNotes app where you started signing in. Never share it with anyone.";
  const code =
    result.confirmationCode === undefined
      ? ""
      : `<p class="code" aria-label="Confirmation code">${result.confirmationCode}</p>`;
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · TaskNotes</title>
<style nonce="${nonce}">body{font:1.125rem/1.6 system-ui,sans-serif;color:#292724;background:#faf9f6;margin:0}main{max-width:32rem;margin:12vh auto;padding:1.5rem}h1{font-size:1.6rem;line-height:1.3}.code{font:2rem/1.5 ui-monospace,monospace;letter-spacing:.18em;overflow-wrap:anywhere}</style>
</head><body><main><h1>${title}</h1><p>${message}</p>${code}</main></body></html>`,
    {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "content-security-policy": `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      },
    },
  );
}
