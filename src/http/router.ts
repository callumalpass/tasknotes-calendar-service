import {
  MAX_JSON_BODY_BYTES,
  ServiceCredentialSchema,
  routes,
  type RouteDefinition,
  type RouteName,
} from "../contracts";
import { ContractError, errorResponse, jsonResponse, noContentResponse } from "./responses";

export interface AuthenticatedRouteContext {
  readonly principalId: string;
  readonly sessionId: string;
  readonly session: Readonly<{
    readonly id: string;
    readonly deviceName: string;
    readonly clientKind: "web" | "ios" | "android" | "obsidian";
    readonly createdAt: string;
    readonly lastUsedAt: string;
    readonly idleExpiresAt: string;
    readonly absoluteExpiresAt: string;
    readonly revokedAt: string | null;
  }>;
}

export interface RouteInput {
  readonly params: Readonly<Record<string, string>>;
  readonly query: unknown;
  readonly body?: unknown;
  readonly authenticated?: AuthenticatedRouteContext;
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
      readonly absoluteExpiresAt: string;
      readonly revokedAt: string | null;
    };
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

async function authenticate(
  request: Request,
  authentication: RouterAuthentication,
): Promise<AuthenticatedRouteContext> {
  const credential = parseBearerCredential(request);
  if (credential === null) throw new AuthenticationRequiredError();
  let result;
  try {
    result = await authentication.authenticate(credential);
  } catch {
    throw new Error("Authentication dependency failed");
  }
  if (result === null) throw new AuthenticationRequiredError();
  const session = Object.freeze({ ...result.session });
  return Object.freeze({ principalId: result.principalId, sessionId: session.id, session });
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

async function dispatch(
  route: CompiledRoute,
  match: RegExpExecArray,
  request: Request,
  handlers: RouteHandlers,
  authentication: RouterAuthentication,
  rateLimiter: RateLimit,
  ctx: ExecutionContext,
): Promise<Response> {
  const authenticated = route.definition.authenticated
    ? await authenticate(request, authentication)
    : undefined;
  if (route.definition.rateLimit !== "none") {
    const key =
      authenticated === undefined
        ? `ip:${request.headers.get("cf-connecting-ip") ?? ""}`
        : `principal:${authenticated.principalId}`;
    let success: boolean;
    try {
      ({ success } = await rateLimiter.limit({ key }));
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
    ...(route.definition.body === undefined ? {} : { body }),
    ...(authenticated === undefined ? {} : { authenticated }),
  });
  const output = await handlers[route.definition.name](input, request, ctx);

  if (route.definition.response === undefined) {
    if (output !== undefined) throw new Error("No-content handler returned a response body");
    return noContentResponse();
  }
  const responseResult = route.definition.response.safeParse(output);
  if (!responseResult.success) throw new Error("Handler response violated its contract");
  if (responseResult.data instanceof Response) return responseResult.data;
  return jsonResponse(responseResult.data, route.definition.successStatus);
}

export function createRouter(
  handlers: RouteHandlers,
  authentication: RouterAuthentication,
  policy: {
    readonly rateLimiter: RateLimit;
    readonly allowedOrigins: () => readonly string[];
    readonly publicOrigin: () => string;
  },
): (request: Request, ctx: ExecutionContext) => Promise<Response> {
  return async (request, ctx) => {
    const requestId = crypto.randomUUID();
    const started = performance.now();
    let routeName: RouteName | "unmatched" = "unmatched";
    let errorCode: string | null = null;
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
          policy.rateLimiter,
          ctx,
        );
      }
    } catch (error) {
      if (error instanceof AuthenticationRequiredError) {
        errorCode = "authentication_required";
        response = errorResponse("authentication_required");
      } else if (error instanceof InvalidInputError || error instanceof ContractError) {
        errorCode = error.code;
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
    });
    return response;
  };
}
