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
}

export interface RouteInput {
  readonly params: Readonly<Record<string, string>>;
  readonly query: unknown;
  readonly body?: unknown;
  readonly authenticated?: AuthenticatedRouteContext;
}

export interface RouterAuthentication {
  authenticate(
    credential: string,
  ): Promise<{ readonly principalId: string; readonly session: { readonly id: string } } | null>;
}

export type RouteHandler = (input: RouteInput, request: Request) => Promise<unknown>;
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
  return Object.freeze({ principalId: result.principalId, sessionId: result.session.id });
}

function parseQuery(url: URL): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const [key, value] of url.searchParams) {
    if (Object.hasOwn(parsed, key)) throw new InvalidInputError("invalid_request");
    parsed[key] = value;
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
): Promise<Response> {
  const authenticated = route.definition.authenticated
    ? await authenticate(request, authentication)
    : undefined;
  const url = new URL(request.url);
  const queryResult = route.definition.query.safeParse(parseQuery(url));
  if (!queryResult.success) throw new InvalidInputError("invalid_request");

  const params = parseParameters(route, match);
  let body: unknown;
  if (route.definition.body !== undefined) {
    const bodyResult = route.definition.body.safeParse(await readBoundedJson(request));
    if (!bodyResult.success) throw new InvalidInputError("invalid_request");
    body = bodyResult.data;
  } else if (request.body !== null) {
    throw new InvalidInputError("invalid_request");
  }

  const input: RouteInput = Object.freeze({
    params,
    query: queryResult.data,
    ...(route.definition.body === undefined ? {} : { body }),
    ...(authenticated === undefined ? {} : { authenticated }),
  });
  const output = await handlers[route.definition.name](input, request);

  if (route.definition.response === undefined) {
    if (output !== undefined) throw new Error("No-content handler returned a response body");
    return noContentResponse();
  }
  const responseResult = route.definition.response.safeParse(output);
  if (!responseResult.success) throw new Error("Handler response violated its contract");
  return jsonResponse(responseResult.data, route.definition.successStatus);
}

export function createRouter(
  handlers: RouteHandlers,
  authentication: RouterAuthentication,
): (request: Request) => Promise<Response> {
  return async (request) => {
    const url = new URL(request.url);
    for (const route of compiledRoutes) {
      if (request.method !== route.definition.method) continue;
      const match = route.expression.exec(url.pathname);
      if (match === null) continue;
      try {
        return await dispatch(route, match, request, handlers, authentication);
      } catch (error) {
        if (error instanceof AuthenticationRequiredError) {
          return errorResponse("authentication_required");
        }
        if (error instanceof InvalidInputError) return errorResponse(error.code);
        if (error instanceof ContractError) {
          return errorResponse(error.code, error.retryAfterSeconds);
        }
        return errorResponse("internal_error");
      }
    }
    return errorResponse("resource_not_found");
  };
}
