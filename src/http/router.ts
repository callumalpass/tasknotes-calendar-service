import {
  MAX_JSON_BODY_BYTES,
  ServiceCredentialSchema,
  routes,
  type RouteDefinition,
  type RouteName,
} from "../contracts";
import { IDLE_LIFETIME_SECONDS } from "../auth/device-sessions";
import { ContractError, errorResponse, jsonResponse, noContentResponse } from "./responses";
import { CLEARED_SESSION_COOKIE, parseSessionCookie, sessionCookie } from "./session-cookie";

export interface AuthenticatedRouteContext {
  readonly principalId: string;
  readonly sessionId: string;
  readonly transport: "bearer" | "cookie";
  readonly session: Readonly<{
    readonly id: string;
    readonly deviceName: string;
    readonly clientKind: "web" | "ios" | "android" | "obsidian";
    readonly createdAt: string;
    readonly lastUsedAt: string;
    readonly idleExpiresAt: string;
    readonly revokedAt: string | null;
  }>;
}

/**
 * What a handler adds to its request's log line. Counts and stable codes only: never a title, an
 * identifier, or anything else a person or the provider wrote.
 */
export interface RequestLog {
  /** Provider items left out of a successful response because the contract cannot carry them. */
  omittedCount?: number;
  /** A successful response that is knowingly incomplete, such as a calendar list cut at its bound. */
  detail?: string;
}

export interface RouteInput {
  readonly params: Readonly<Record<string, string>>;
  readonly query: unknown;
  readonly body?: unknown;
  readonly originAllowed: boolean;
  readonly authenticated?: AuthenticatedRouteContext;
  readonly log: RequestLog;
}

export interface RouterAuthentication {
  authenticate(credential: string): Promise<{
    readonly principalId: string;
    readonly session: {
      readonly id: string;
      readonly deviceName: string;
      readonly clientKind: "web" | "ios" | "android" | "obsidian";
      readonly createdAt: string;
      readonly lastUsedAt: string;
      readonly idleExpiresAt: string;
      readonly revokedAt: string | null;
    };
    /** This use began the session's idle period again. */
    readonly renewed: boolean;
  } | null>;
}

export type RouteHandler = (
  input: RouteInput,
  request: Request,
  ctx: ExecutionContext,
) => Promise<unknown>;
export type RouteHandlers = Readonly<Record<RouteName, RouteHandler>>;

class InvalidInputError extends Error {
  constructor(readonly code: "invalid_request" | "unsupported_media_type" | "payload_too_large") {
    super(code);
  }
}

class AuthenticationRequiredError extends Error {}

interface CompiledRoute {
  readonly definition: RouteDefinition;
  readonly expression: RegExp;
  readonly parameterNames: readonly string[];
}

function compileRoute(definition: RouteDefinition): CompiledRoute {
  const parameterNames: string[] = [];
  const source = definition.path
    .split("/")
    .map((segment) => {
      const match = /^\{([a-z_]+)\}$/.exec(segment);
      if (match?.[1] !== undefined) {
        parameterNames.push(match[1]);
        return "([^/]+)";
      }
      return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  return { definition, expression: new RegExp(`^${source}$`), parameterNames };
}

const compiledRoutes = routes.map(compileRoute);

function parseBearerCredential(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  const result = ServiceCredentialSchema.safeParse(authorization.slice("Bearer ".length));
  return result.success ? result.data : null;
}

interface Authentication {
  readonly context: AuthenticatedRouteContext;
  /** Set when a web session's idle period began again: its cookie must outlive it too. */
  readonly renewedCookie?: string;
}

async function authenticate(
  request: Request,
  authentication: RouterAuthentication,
  originAllowed: boolean,
): Promise<Authentication> {
  const transport = request.headers.has("authorization") ? "bearer" : "cookie";
  const credential =
    transport === "bearer" ? parseBearerCredential(request) : parseSessionCookie(request);
  if (credential === null) throw new AuthenticationRequiredError();
  if (transport === "cookie" && !originAllowed) throw new ContractError("permission_denied");
  let result;
  try {
    result = await authentication.authenticate(credential);
  } catch {
    throw new Error("Authentication dependency failed");
  }
  if (result === null) throw new AuthenticationRequiredError();
  // ADR 0006: a session's client kind fixes its transport.
  if ((result.session.clientKind === "web") !== (transport === "cookie")) {
    throw new AuthenticationRequiredError();
  }
  const session = Object.freeze({ ...result.session });
  const context = Object.freeze({
    principalId: result.principalId,
    sessionId: session.id,
    transport,
    session,
  });
  return result.renewed && transport === "cookie"
    ? { context, renewedCookie: sessionCookie(credential, IDLE_LIFETIME_SECONDS) }
    : { context };
}

function parseQuery(url: URL): Record<string, string | string[]> {
  const parsed: Record<string, string | string[]> = {};
  for (const [key, value] of url.searchParams) {
    parsed[key] = Object.hasOwn(parsed, key) ? [...url.searchParams.getAll(key)] : value;
  }
  return parsed;
}

function hasJsonContentType(request: Request): boolean {
  const value = request.headers.get("content-type");
  if (value === null) return false;
  const parts = value.split(";").map((part) => part.trim().toLowerCase());
  if (parts.shift() !== "application/json" || parts.length > 1) return false;
  return parts.length === 0 || parts[0] === "charset=utf-8";
}

async function assertEmptyBody(request: Request): Promise<void> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) throw new InvalidInputError("invalid_request");
    if (Number(declaredLength) > 0) throw new InvalidInputError("invalid_request");
  }
  if (request.body === null) return;

  const reader = request.body.getReader();
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) return;
      if (result.value.byteLength > 0) {
        await reader.cancel();
        throw new InvalidInputError("invalid_request");
      }
    }
  } finally {
    reader.releaseLock();
  }
}

async function readBoundedJson(request: Request): Promise<unknown> {
  if (!hasJsonContentType(request)) throw new InvalidInputError("unsupported_media_type");

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) throw new InvalidInputError("invalid_request");
    if (Number(declaredLength) > MAX_JSON_BODY_BYTES) {
      throw new InvalidInputError("payload_too_large");
    }
  }
  if (request.body === null) throw new InvalidInputError("invalid_request");

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > MAX_JSON_BODY_BYTES) {
        await reader.cancel();
        throw new InvalidInputError("payload_too_large");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch {
    throw new InvalidInputError("invalid_request");
  }
}

function parseParameters(route: CompiledRoute, match: RegExpExecArray): Record<string, string> {
  const raw: Record<string, string> = {};
  route.parameterNames.forEach((name, index) => {
    const value = match[index + 1];
    if (value === undefined) throw new Error("Missing compiled route parameter");
    try {
      raw[name] = decodeURIComponent(value);
    } catch {
      throw new InvalidInputError("invalid_request");
    }
  });
  const result: Record<string, string> = {};
  for (const [name, schema] of Object.entries(route.definition.params)) {
    const parsed = schema.safeParse(raw[name]);
    if (!parsed.success || typeof parsed.data !== "string") {
      throw new InvalidInputError("invalid_request");
    }
    result[name] = parsed.data;
  }
  return result;
}

function endsOwnSession(
  route: CompiledRoute,
  params: Readonly<Record<string, string>>,
  authenticated: AuthenticatedRouteContext,
): boolean {
  return (
    route.definition.name === "deleteAccount" ||
    (route.definition.name === "revokeDevice" && params["device_id"] === authenticated.sessionId)
  );
}

/** Sign-in is limited per address; a signed-in person has their own, larger allowance. */
export interface RateLimiters {
  readonly ip: RateLimit;
  readonly principal: RateLimit;
}

async function dispatch(
  route: CompiledRoute,
  match: RegExpExecArray,
  request: Request,
  handlers: RouteHandlers,
  authentication: RouterAuthentication,
  rateLimiters: RateLimiters,
  originAllowed: boolean,
  ctx: ExecutionContext,
  log: RequestLog,
): Promise<Response> {
  const authentic = route.definition.authenticated
    ? await authenticate(request, authentication, originAllowed)
    : undefined;
  const authenticated = authentic?.context;
  if (route.definition.rateLimit !== "none") {
    const key =
      authenticated === undefined
        ? `ip:${request.headers.get("cf-connecting-ip") ?? ""}`
        : `principal:${authenticated.principalId}`;
    let success: boolean;
    try {
      ({ success } = await rateLimiters[route.definition.rateLimit].limit({ key }));
    } catch {
      // Fail closed: an unavailable abuse boundary must not expose unbounded OAuth/provider work.
      throw new ContractError("dependency_unavailable", 60);
    }
    if (!success) throw new ContractError("rate_limited", 60);
  }
  const url = new URL(request.url);
  const queryResult = route.definition.query.safeParse(parseQuery(url));
  if (!queryResult.success) throw new InvalidInputError("invalid_request");

  for (const header of route.definition.requiredHeaders ?? []) {
    const value = request.headers.get(header);
    if (
      value === null ||
      value.length === 0 ||
      value.length > 256 ||
      !/^[\x21-\x7e]+$/u.test(value)
    )
      throw new InvalidInputError("invalid_request");
  }
  const params = parseParameters(route, match);
  let body: unknown;
  if (route.definition.body !== undefined) {
    const bodyResult = route.definition.body.safeParse(await readBoundedJson(request));
    if (!bodyResult.success) throw new InvalidInputError("invalid_request");
    body = bodyResult.data;
  } else {
    await assertEmptyBody(request);
  }

  const input: RouteInput = Object.freeze({
    params,
    query: queryResult.data,
    originAllowed,
    log,
    ...(route.definition.body === undefined ? {} : { body }),
    ...(authenticated === undefined ? {} : { authenticated }),
  });
  const output = await handlers[route.definition.name](input, request, ctx);

  if (route.definition.response === undefined) {
    if (output !== undefined) throw new Error("No-content handler returned a response body");
    const response = noContentResponse();
    if (authenticated?.transport === "cookie" && endsOwnSession(route, params, authenticated)) {
      response.headers.set("set-cookie", CLEARED_SESSION_COOKIE);
    } else if (authentic?.renewedCookie !== undefined) {
      response.headers.set("set-cookie", authentic.renewedCookie);
    }
    return response;
  }
  const responseResult = route.definition.response.safeParse(output);
  if (!responseResult.success) throw new Error("Handler response violated its contract");
  const response =
    responseResult.data instanceof Response
      ? responseResult.data
      : jsonResponse(responseResult.data, route.definition.successStatus);
  if (authentic?.renewedCookie !== undefined) {
    response.headers.set("set-cookie", authentic.renewedCookie);
  }
  return response;
}

export function createRouter(
  handlers: RouteHandlers,
  authentication: RouterAuthentication,
  policy: {
    readonly rateLimiters: RateLimiters;
    readonly allowedOrigins: () => readonly string[];
    readonly publicOrigin: () => string;
  },
): (request: Request, ctx: ExecutionContext) => Promise<Response> {
  return async (request, ctx) => {
    const requestId = crypto.randomUUID();
    const started = performance.now();
    let routeName: RouteName | "unmatched" = "unmatched";
    let errorCode: string | null = null;
    let detail: string | undefined;
    const log: RequestLog = {};
    let allowedOrigin: string | undefined;
    let response: Response;
    try {
      const url = new URL(request.url);
      if (url.origin !== policy.publicOrigin()) throw new ContractError("resource_not_found");
      const origin = request.headers.get("origin");
      if (origin !== null && policy.allowedOrigins().includes(origin)) allowedOrigin = origin;
      const method =
        request.method === "OPTIONS"
          ? request.headers.get("access-control-request-method")
          : request.method;
      const route = compiledRoutes.find(
        (candidate) =>
          candidate.definition.method === method && candidate.expression.test(url.pathname),
      );
      if (route === undefined) throw new ContractError("resource_not_found");
      routeName = route.definition.name;
      const match = route.expression.exec(url.pathname);
      if (match === null) throw new Error("Compiled route did not match");
      if (request.method === "OPTIONS") {
        parseParameters(route, match);
        const headers = request.headers.get("access-control-request-headers");
        if (
          allowedOrigin === undefined ||
          headers
            ?.split(",")
            .some(
              (header) =>
                !["authorization", "content-type", "if-match"].includes(
                  header.trim().toLowerCase(),
                ),
            )
        )
          throw new ContractError("permission_denied");
        response = noContentResponse();
        response.headers.set("access-control-allow-methods", route.definition.method);
        response.headers.set(
          "access-control-allow-headers",
          "Authorization, Content-Type, If-Match",
        );
      } else {
        response = await dispatch(
          route,
          match,
          request,
          handlers,
          authentication,
          policy.rateLimiters,
          allowedOrigin !== undefined,
          ctx,
          log,
        );
        detail = log.detail;
      }
    } catch (error) {
      if (error instanceof AuthenticationRequiredError) {
        errorCode = "authentication_required";
        response = errorResponse("authentication_required");
      } else if (error instanceof InvalidInputError || error instanceof ContractError) {
        errorCode = error.code;
        if (error instanceof ContractError) detail = error.detail;
        response = errorResponse(
          error.code,
          error instanceof ContractError ? error.retryAfterSeconds : undefined,
        );
      } else {
        errorCode = "internal_error";
        console.error({
          error_class: error instanceof Error ? error.constructor.name : "NonError",
          location: "http.router",
        });
        response = errorResponse("internal_error");
      }
    }
    response.headers.set("x-request-id", requestId);
    response.headers.append("vary", "Origin");
    if (allowedOrigin !== undefined) {
      response.headers.set("access-control-allow-origin", allowedOrigin);
      response.headers.set("access-control-allow-credentials", "true");
      response.headers.set("access-control-expose-headers", "x-request-id, Retry-After");
    }
    console.log({
      request_id: requestId,
      route: routeName,
      method: request.method,
      status: response.status,
      duration_ms: Math.round(performance.now() - started),
      error_code: errorCode,
      retry_after: response.headers.get("retry-after"),
      detail: detail ?? null,
      omitted_count: log.omittedCount ?? null,
    });
    return response;
  };
}
