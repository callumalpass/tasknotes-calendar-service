import { decodeProtectedHeader, jwtVerify } from "jose";
import type { JWTVerifyGetKey, JWTPayload } from "jose";

const CANONICAL_ISSUER = "https://accounts.google.com";
const ACCEPTED_ISSUERS = new Set([CANONICAL_ISSUER, "accounts.google.com"]);
const IDENTITY_SCOPES = ["openid", "email", "profile"] as const;
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;
const OAUTH_VALUE = /^[\u0021-\u007e]+$/;
const ALLOWED_CALENDAR_SCOPES = new Set([
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events.readonly",
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
]);
const MAX_PARAMETER_BYTES = 2_048;
const MAX_TOKEN_BYTES = 16_384;
const MAX_ID_TOKEN_BYTES = 32_768;
const MAX_RESPONSE_BYTES = 65_536;
const MAX_CLAIM_BYTES = 2_048;
const MAX_SCOPES = 32;
const MAX_EXPIRES_IN_SECONDS = 86_400;
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_MAX_ID_TOKEN_AGE_SECONDS = 3_600;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export interface GoogleOidcEndpoints {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
}

export interface GoogleOidcClient {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
}

export interface GoogleAuthorizationInput {
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
}

export interface GoogleCalendarAuthorizationInput extends GoogleAuthorizationInput {
  readonly calendarScopes: readonly string[];
}

export interface GoogleTokenExchangeInput {
  readonly code: string;
  readonly codeVerifier: string;
  readonly expectedNonce: string;
}

export interface GoogleCalendarTokenExchangeInput extends GoogleTokenExchangeInput {
  readonly expectedSubject: string;
  readonly requiredCalendarScopes: readonly string[];
}

export interface GoogleIdentity {
  readonly issuer: typeof CANONICAL_ISSUER;
  readonly subject: string;
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
}

export interface GoogleCalendarConnectionResult {
  readonly identity: GoogleIdentity;
  readonly tokenMaterial: {
    readonly accessToken: string;
    readonly refreshToken: string;
    readonly expiresInSeconds: number;
    readonly scopes: readonly string[];
  };
}

export interface GoogleOidcDependencies {
  readonly fetch: typeof fetch;
  readonly keyResolver: JWTVerifyGetKey;
  readonly nowEpochSeconds?: () => number;
  readonly timeoutMilliseconds?: number;
  readonly clockSkewSeconds?: number;
  readonly maximumIdTokenAgeSeconds?: number;
}

export type GoogleOidcErrorCode =
  | "invalid_request"
  | "provider_exchange_failed"
  | "invalid_token_response"
  | "invalid_id_token"
  | "identity_mismatch"
  | "insufficient_scope";

export class GoogleOidcError extends Error {
  public readonly code: GoogleOidcErrorCode;

  public constructor(code: GoogleOidcErrorCode) {
    super("Google authorization could not be completed");
    this.name = "GoogleOidcError";
    this.code = code;
  }
}

interface TokenResponse {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresInSeconds: number;
  readonly idToken: string;
  readonly scopes: readonly string[];
}

function fail(code: GoogleOidcErrorCode): never {
  throw new GoogleOidcError(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertBoundedAscii(value: string, maximumBytes = MAX_PARAMETER_BYTES): void {
  if (
    value.length === 0 ||
    !OAUTH_VALUE.test(value) ||
    textEncoder.encode(value).length > maximumBytes
  ) {
    fail("invalid_request");
  }
}

function assertEndpoint(value: string): URL {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== ""
    ) {
      fail("invalid_request");
    }
    return url;
  } catch {
    return fail("invalid_request");
  }
}

function validateCommonAuthorization(input: GoogleAuthorizationInput): void {
  assertBoundedAscii(input.state);
  assertBoundedAscii(input.nonce);
  if (!PKCE_CHALLENGE.test(input.codeChallenge)) fail("invalid_request");
}

function validateCalendarScopes(scopes: readonly string[]): string[] {
  if (scopes.length === 0 || scopes.length > MAX_SCOPES) fail("invalid_request");
  const unique = new Set<string>();
  for (const scope of scopes) {
    assertBoundedAscii(scope, 256);
    if (!ALLOWED_CALENDAR_SCOPES.has(scope)) fail("invalid_request");
    unique.add(scope);
  }
  if (unique.size !== scopes.length) fail("invalid_request");
  return [...unique];
}

function authorizationUrl(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleAuthorizationInput,
  scopes: readonly string[],
  calendar: boolean,
): URL {
  validateCommonAuthorization(input);
  assertBoundedAscii(client.clientId);
  assertBoundedAscii(client.redirectUri);
  const url = assertEndpoint(endpoints.authorizationEndpoint);
  url.search = "";
  url.searchParams.set("client_id", client.clientId);
  url.searchParams.set("redirect_uri", client.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (calendar) {
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("include_granted_scopes", "true");
    url.searchParams.set("prompt", "consent");
  }
  return url;
}

export function createGoogleSignInAuthorizationUrl(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleAuthorizationInput,
): URL {
  return authorizationUrl(endpoints, client, input, IDENTITY_SCOPES, false);
}

export function createGoogleCalendarAuthorizationUrl(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleCalendarAuthorizationInput,
): URL {
  const calendarScopes = validateCalendarScopes(input.calendarScopes);
  return authorizationUrl(endpoints, client, input, [...IDENTITY_SCOPES, ...calendarScopes], true);
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const type = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (type !== "application/json") fail("invalid_token_response");
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE_BYTES)) {
    fail("invalid_token_response");
  }
  if (response.body === null) fail("invalid_token_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        fail("invalid_token_response");
      }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(textDecoder.decode(bytes)) as unknown;
  } catch (error) {
    if (error instanceof GoogleOidcError) throw error;
    return fail("invalid_token_response");
  }
}

function boundedToken(value: unknown, maximumBytes = MAX_TOKEN_BYTES): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    textEncoder.encode(value).length > maximumBytes
  ) {
    return fail("invalid_token_response");
  }
  return value;
}

function parseScopes(value: unknown): string[] {
  if (typeof value !== "string" || textEncoder.encode(value).length > MAX_PARAMETER_BYTES) {
    return fail("invalid_token_response");
  }
  const scopes = value.split(" ").filter((scope) => scope.length > 0);
  if (scopes.length === 0 || scopes.length > MAX_SCOPES || new Set(scopes).size !== scopes.length) {
    return fail("invalid_token_response");
  }
  for (const scope of scopes) assertBoundedAscii(scope, 256);
  return scopes;
}

function parseTokenResponse(value: unknown): TokenResponse {
  if (!isRecord(value)) fail("invalid_token_response");
  const expires = value["expires_in"];
  if (
    !Number.isSafeInteger(expires) ||
    (expires as number) < 1 ||
    (expires as number) > MAX_EXPIRES_IN_SECONDS
  ) {
    fail("invalid_token_response");
  }
  if (value["token_type"] !== "Bearer") fail("invalid_token_response");
  const refresh = value["refresh_token"];
  if (refresh !== undefined && typeof refresh !== "string") fail("invalid_token_response");
  return {
    accessToken: boundedToken(value["access_token"]),
    ...(refresh === undefined ? {} : { refreshToken: boundedToken(refresh) }),
    expiresInSeconds: expires as number,
    idToken: boundedToken(value["id_token"], MAX_ID_TOKEN_BYTES),
    scopes: parseScopes(value["scope"]),
  };
}

async function exchangeCode(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleTokenExchangeInput,
  dependencies: GoogleOidcDependencies,
): Promise<TokenResponse> {
  assertBoundedAscii(client.clientId);
  assertBoundedAscii(client.clientSecret, MAX_TOKEN_BYTES);
  assertBoundedAscii(client.redirectUri);
  assertBoundedAscii(input.code, MAX_TOKEN_BYTES);
  if (!PKCE_VERIFIER.test(input.codeVerifier)) fail("invalid_request");
  assertBoundedAscii(input.expectedNonce);
  const tokenEndpoint = assertEndpoint(endpoints.tokenEndpoint);
  const timeout = dependencies.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30_000) fail("invalid_request");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    client_id: client.clientId,
    client_secret: client.clientSecret,
    redirect_uri: client.redirectUri,
    code_verifier: input.codeVerifier,
  });
  let response: Response;
  try {
    response = await dependencies.fetch(tokenEndpoint, {
      method: "POST",
      headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(timeout),
    });
  } catch {
    return fail("provider_exchange_failed");
  }
  if (!response.ok) {
    try {
      await readBoundedJson(response);
    } catch {
      // Provider details are deliberately discarded.
    }
    return fail("provider_exchange_failed");
  }
  return parseTokenResponse(await readBoundedJson(response));
}

function boundedClaim(value: unknown, required: boolean): string | undefined {
  if (value === undefined && !required) return undefined;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    textEncoder.encode(value).length > MAX_CLAIM_BYTES
  ) {
    return fail("invalid_id_token");
  }
  return value;
}

function integerClaim(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return fail("invalid_id_token");
  }
  return value;
}

function validateAudience(payload: JWTPayload, clientId: string): void {
  const audiences = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (!Array.isArray(audiences) || audiences.length === 0 || audiences.length > 10)
    fail("invalid_id_token");
  if (
    audiences.some(
      (audience) =>
        typeof audience !== "string" ||
        audience.length === 0 ||
        textEncoder.encode(audience).length > MAX_CLAIM_BYTES,
    )
  )
    fail("invalid_id_token");
  if (audiences.filter((audience) => audience === clientId).length !== 1) fail("invalid_id_token");
  const azp = boundedClaim(payload["azp"], false);
  if (audiences.length > 1 && azp !== clientId) fail("invalid_id_token");
  if (azp !== undefined && azp !== clientId) fail("invalid_id_token");
}

async function verifyIdentity(
  idToken: string,
  expectedNonce: string,
  clientId: string,
  dependencies: GoogleOidcDependencies,
): Promise<GoogleIdentity> {
  const now = dependencies.nowEpochSeconds?.() ?? Math.floor(Date.now() / 1_000);
  const skew = dependencies.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const maxAge = dependencies.maximumIdTokenAgeSeconds ?? DEFAULT_MAX_ID_TOKEN_AGE_SECONDS;
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(skew) ||
    skew < 0 ||
    skew > 300 ||
    !Number.isSafeInteger(maxAge) ||
    maxAge < 1 ||
    maxAge > 7_200
  ) {
    fail("invalid_request");
  }
  try {
    const header = decodeProtectedHeader(idToken);
    if (header.alg !== "RS256" || boundedClaim(header.kid, true) === undefined)
      fail("invalid_id_token");
    const verified = await jwtVerify(idToken, dependencies.keyResolver, {
      algorithms: ["RS256"],
      currentDate: new Date(now * 1_000),
      clockTolerance: skew,
    });
    const payload = verified.payload;
    const issuer = boundedClaim(payload.iss, true);
    if (issuer === undefined || !ACCEPTED_ISSUERS.has(issuer)) fail("invalid_id_token");
    validateAudience(payload, clientId);
    if (boundedClaim(payload["nonce"], true) !== expectedNonce) fail("invalid_id_token");
    const subject = boundedClaim(payload.sub, true);
    if (subject === undefined) fail("invalid_id_token");
    const issuedAt = integerClaim(payload.iat);
    const expiresAt = integerClaim(payload.exp);
    if (
      issuedAt > now + skew ||
      issuedAt < now - maxAge - skew ||
      expiresAt <= now - skew ||
      expiresAt > issuedAt + maxAge + skew
    ) {
      fail("invalid_id_token");
    }
    if (payload.nbf !== undefined && integerClaim(payload.nbf) > now + skew)
      fail("invalid_id_token");
    const email = boundedClaim(payload["email"], false);
    const name = boundedClaim(payload["name"], false);
    const emailVerified = payload["email_verified"];
    if (emailVerified !== undefined && typeof emailVerified !== "boolean") fail("invalid_id_token");
    return {
      issuer: CANONICAL_ISSUER,
      subject,
      ...(email === undefined ? {} : { email }),
      ...(emailVerified === undefined ? {} : { emailVerified }),
      ...(name === undefined ? {} : { name }),
    };
  } catch (error) {
    if (error instanceof GoogleOidcError && error.code === "invalid_request") throw error;
    return fail("invalid_id_token");
  }
}

export async function exchangeGoogleSignInCode(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleTokenExchangeInput,
  dependencies: GoogleOidcDependencies,
): Promise<GoogleIdentity> {
  const tokens = await exchangeCode(endpoints, client, input, dependencies);
  return verifyIdentity(tokens.idToken, input.expectedNonce, client.clientId, dependencies);
}

export async function exchangeGoogleCalendarCode(
  endpoints: GoogleOidcEndpoints,
  client: GoogleOidcClient,
  input: GoogleCalendarTokenExchangeInput,
  dependencies: GoogleOidcDependencies,
): Promise<GoogleCalendarConnectionResult> {
  const required = [...IDENTITY_SCOPES, ...validateCalendarScopes(input.requiredCalendarScopes)];
  assertBoundedAscii(input.expectedSubject);
  const tokens = await exchangeCode(endpoints, client, input, dependencies);
  const identity = await verifyIdentity(
    tokens.idToken,
    input.expectedNonce,
    client.clientId,
    dependencies,
  );
  if (identity.subject !== input.expectedSubject) fail("identity_mismatch");
  if (tokens.refreshToken === undefined) fail("invalid_token_response");
  const granted = new Set(tokens.scopes);
  if (required.some((scope) => !granted.has(scope))) fail("insufficient_scope");
  return {
    identity,
    tokenMaterial: {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresInSeconds: tokens.expiresInSeconds,
      scopes: tokens.scopes,
    },
  };
}
