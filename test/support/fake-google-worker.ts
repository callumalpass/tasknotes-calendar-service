/* A deliberately private, deterministic test provider. Every credential and key in this file is fake. */

const FAKE_GOOGLE_ORIGIN = "http://127.0.0.1:9797";
const FAKE_GOOGLE_CLIENT_ID = "local-fake-google-client";
const FAKE_GOOGLE_CLIENT_SECRET = "test-only-fake-google-secret";
const FAKE_GOOGLE_REDIRECT_URI = "http://127.0.0.1:8787/oauth/google/callback";
const FAKE_GOOGLE_KID = "test-only-fake-google-rs256-1";
const FAKE_CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";

const CONTROL_ORIGIN = "https://fake-google-control.test";
const CANONICAL_ISSUER = "https://accounts.google.com";
const IDENTITY_SCOPES = ["openid", "email", "profile"] as const;
const MAX_FORM_BYTES = 8_192;
const MAX_VALUE_BYTES = 2_048;
const encoder = new TextEncoder();

// Generated once for this test fake. It is not accepted outside the isolated test runtime.
const FAKE_PRIVATE_JWK: JsonWebKey = {
  key_ops: ["sign"],
  ext: true,
  alg: "RS256",
  kty: "RSA",
  n: "5bikiLalpzG3dTbWKyU9nuxiYwyj6UQHlYGGsD1x64dQ471tTSbmq1cuxkoEMyYkc8dyU7ywh1inRJRlwIIfX8K6nYABWJaNmMPGy_xzt1Adp9RP_7r0G19Y6aWRoEO0J8ay-pXa7YWXnP6DZAmWQXGIdjRk8LLLp8L0A74wUn1fvs6ekZB2cJuLIfvY3lcLiWStNgKmH_rGMff1eVAGHzTUPL-ZzP6rq9HitJXoyEAn1NosYwhklPfmuQQWT7ITszKBgOrEvg9L6dds57SCOvGn7LidFtKXir_u7Z_iB2jk9vYIv8bNBs-OC2FwZxrdnMMeCp-P4UCCMEtwnVZydw",
  e: "AQAB",
  d: "Sa_Gp0vfKxhZfrHOVRym_XlZvefqFAMMY7qel52-Ewzet46lpt_ZkhBvIo_PdRDBFJpfY9jczy1yyh7H3M5gffkanzbWN7JjTSNPe1NJUv3R5WnHF4LClp0pChlf8waEnVWxR4wWI6Z8kZFaWBZzKh7e5Pu9fS_8_50bZK_3FB4jqXglhGiQDbfGd6yspCjaizPhZ1cLainvIA0hiu3dku-jwQbVNgZtTxE80CzNjIzoyBbLFFt6CbTQQmPLZZmTdJfN2EBO8f2WrYon_rSWcnE18eOyWfXwR43gT2uva6OtgjVfbAKhpp7NY26EUbPOtDVFjbPM1w36egovr81VYQ",
  p: "9EzVUTRF7NCZRhFeQ-bQzRVpLILr24WkKT39YTp6K-MouvE8VNgIrRZjdfI1yccYgjVlv95VFcfUODPQb1S9YipqjSmfEBszdeBg4t0e9yVdI-Pm0bPaXc1O6OV30atG93TQKTydNJgRWXDo9Wfrn8ynXRvnDnz-og41hMz8hZk",
  q: "8LkR1yklK7UBXcrZAVzfnq5ChAu2h4_fmMObFhuf5iixu1LWLCDUV-a5H9oaMzP6pXCykJMi7Il-dHE6yn92QGa3gltceNDJXdRCt23sQkw2q2dfJodgombIb9cnRjfOIY6uJXG_aOybOyC4DRo3sBakXb7MDmYyH43yoinFoo8",
  dp: "1bE3jtZ4q9Mzn1Sl7iNCVYH7A5JpmRXnKKQutROfti_3er51FYn63NyOl6cMYbmjuJHYtOJX7rti6N553khzeCC-H0he-Imyk9N3LDpbUbf_Jtu9FYWK5y4lbhb6ng6B_wbQ5qE8qbqywle_jpoeQyOS6iD0FXpEiaCAM-_Sm1E",
  dq: "aIZj2cJy8nSJIFnZOn9CVluiZEXVvy1Y0LN23vWly8G10voYJ1cl_PkhP1Rr9fnHBxlVX_OTwZO-Rf94oL8R8MrpOgBDue4m0cg-I_nmEa-YOXsMVOWJr1rkA7QvyIyow-d5dKbcj0nV6am-YWoV7i8WteIIJuR3NT5kscdjmr8",
  qi: "f34nPSUkIteIFy12CdVsZDfTe85qXbt2qmcBTzE3Y9eCkRCnf3HrgKt2t3c8aDf2f79Qm9FLyhM16IlcNCoXoVYEyetXpb0saJqQS2Qo9Kjc0VWTGns3vAPeEwApYo2Jk05AXZ01AxC2dK7qPQtvffiJYIKWohMILhOw67D_pB0",
};
const FAKE_PUBLIC_JWK = {
  kty: "RSA",
  alg: "RS256",
  use: "sig",
  kid: FAKE_GOOGLE_KID,
  n: FAKE_PRIVATE_JWK.n,
  e: FAKE_PRIVATE_JWK.e,
} as const;

type FakeTokenMode =
  | "success"
  | "wrong_nonce"
  | "wrong_issuer"
  | "alternate_issuer"
  | "wrong_audience"
  | "wrong_azp"
  | "wrong_signature"
  | "expired"
  | "omitted_scope"
  | "writable_scope"
  | "missing_refresh_token"
  | "rate_limited"
  | "stall"
  | "consume_then_fail";
type FakeCalendarMode = "success" | "rate_limited" | "malformed";
interface FakeGoogleConfiguration {
  authorization?: "success" | "access_denied" | "unknown_error";
  token?: FakeTokenMode;
  calendar?: FakeCalendarMode;
  calendarEnabled?: boolean;
  subject?: string;
  email?: string;
}
interface FakeGoogleStats {
  authorizationRequests: number;
  tokenRequests: number;
  uniqueCodeExchanges: number;
  revokeCalls: number;
  calendarCalls: number;
  rejectedRequests: number;
}

interface CodeRecord {
  nonce: string;
  redirectUri: string;
  clientId: string;
  scopes: string[];
  challenge: string;
}

const codes = new Map<string, CodeRecord>();
let configuration: Required<FakeGoogleConfiguration>;
let stats: FakeGoogleStats;
let signingKey: Promise<CryptoKey> | undefined;

function reset(): void {
  codes.clear();
  configuration = {
    authorization: "success",
    token: "success",
    calendar: "success",
    calendarEnabled: false,
    subject: "fake-google-subject-001",
    email: "fake.user@example.test",
  };
  stats = {
    authorizationRequests: 0,
    tokenRequests: 0,
    uniqueCodeExchanges: 0,
    revokeCalls: 0,
    calendarCalls: 0,
    rejectedRequests: 0,
  };
}
reset();

function json(value: unknown, status = 200, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json; charset=utf-8");
  if (!responseHeaders.has("cache-control")) responseHeaders.set("cache-control", "no-store");
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

function reject(status = 404): Response {
  stats.rejectedRequests += 1;
  return json({ error: "fake_provider_rejected_request" }, status);
}

function bounded(value: string, maximum = MAX_VALUE_BYTES): boolean {
  return (
    value.length > 0 && encoder.encode(value).byteLength <= maximum && /^[\x21-\x7e]+$/u.test(value)
  );
}

function exactParameters(params: URLSearchParams, names: readonly string[]): boolean {
  const expected = new Set(names);
  const seen = new Set<string>();
  for (const [name] of params) {
    if (!expected.has(name) || seen.has(name)) return false;
    seen.add(name);
  }
  return seen.size === expected.size;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function digest(value: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

function redirectError(callback: string, state: string, error: string): Response {
  const location = new URL(callback);
  location.searchParams.set("error", error);
  location.searchParams.set("state", state);
  location.searchParams.set("error_description", "The fake provider denied this test request.");
  location.searchParams.set("error_uri", "https://fake-google-control.test/errors/denied");
  return new Response(null, {
    status: 302,
    headers: { location: location.href, "cache-control": "no-store" },
  });
}

function authorize(request: Request, url: URL): Response {
  stats.authorizationRequests += 1;
  if (request.method !== "GET") return reject(405);
  const base = [
    "client_id",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
  ];
  const hasOffline = url.searchParams.has("access_type") || url.searchParams.has("prompt");
  const names = hasOffline ? [...base, "access_type", "prompt"] : base;
  if (!exactParameters(url.searchParams, names)) return reject(400);
  const get = (name: string): string => url.searchParams.get(name) ?? "";
  const scope = get("scope").split(" ");
  const calendar = scope.includes(FAKE_CALENDAR_SCOPE);
  const validScopes =
    scope.length === (calendar ? 4 : 3) &&
    new Set(scope).size === scope.length &&
    IDENTITY_SCOPES.every((item) => scope.includes(item)) &&
    scope.every(
      (item) =>
        IDENTITY_SCOPES.includes(item as (typeof IDENTITY_SCOPES)[number]) ||
        item === FAKE_CALENDAR_SCOPE,
    );
  if (
    get("client_id") !== FAKE_GOOGLE_CLIENT_ID ||
    get("redirect_uri") !== FAKE_GOOGLE_REDIRECT_URI ||
    get("response_type") !== "code" ||
    !validScopes ||
    !bounded(get("state")) ||
    !bounded(get("nonce")) ||
    !/^[A-Za-z0-9_-]{43}$/u.test(get("code_challenge")) ||
    get("code_challenge_method") !== "S256" ||
    (hasOffline && (!calendar || get("access_type") !== "offline" || get("prompt") !== "consent"))
  )
    return reject(400);

  const authorization = configuration.authorization;
  configuration.authorization = "success";
  if (authorization === "access_denied")
    return redirectError(FAKE_GOOGLE_REDIRECT_URI, get("state"), "access_denied");
  if (authorization === "unknown_error")
    return redirectError(FAKE_GOOGLE_REDIRECT_URI, get("state"), "fake_unknown_oauth_error");

  const code = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  codes.set(code, {
    nonce: get("nonce"),
    redirectUri: get("redirect_uri"),
    clientId: get("client_id"),
    scopes: scope,
    challenge: get("code_challenge"),
  });
  const callback = new URL(FAKE_GOOGLE_REDIRECT_URI);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", get("state"));
  callback.searchParams.set("scope", scope.join(" "));
  callback.searchParams.set("authuser", "0");
  callback.searchParams.set("prompt", calendar ? "consent" : "none");
  callback.searchParams.set("iss", CANONICAL_ISSUER);
  return new Response(null, {
    status: 302,
    headers: { location: callback.href, "cache-control": "no-store" },
  });
}

async function strictForm(
  request: Request,
  names: readonly string[],
): Promise<URLSearchParams | undefined> {
  if (
    request.headers.get("content-type")?.trim().toLowerCase() !==
    "application/x-www-form-urlencoded"
  )
    return undefined;
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_FORM_BYTES))
    return undefined;
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > MAX_FORM_BYTES) return undefined;
  const form = new URLSearchParams(new TextDecoder().decode(bytes));
  return exactParameters(form, names) ? form : undefined;
}

async function sign(payload: Record<string, unknown>, wrongKid: boolean): Promise<string> {
  const header = base64Url(
    encoder.encode(
      JSON.stringify({
        alg: "RS256",
        kid: wrongKid ? "unpublished-test-key" : FAKE_GOOGLE_KID,
        typ: "JWT",
      }),
    ),
  );
  const body = base64Url(encoder.encode(JSON.stringify(payload)));
  signingKey ??= crypto.subtle.importKey(
    "jwk",
    FAKE_PRIVATE_JWK,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    await signingKey,
    encoder.encode(`${header}.${body}`),
  );
  return `${header}.${body}.${base64Url(new Uint8Array(signature))}`;
}

async function token(request: Request): Promise<Response> {
  stats.tokenRequests += 1;
  if (request.method !== "POST") return reject(405);
  const form = await strictForm(request, [
    "grant_type",
    "code",
    "client_id",
    "client_secret",
    "redirect_uri",
    "code_verifier",
  ]);
  if (form === undefined) return reject(400);
  const code = form.get("code") ?? "";
  if (
    form.get("grant_type") !== "authorization_code" ||
    form.get("client_id") !== FAKE_GOOGLE_CLIENT_ID ||
    form.get("client_secret") !== FAKE_GOOGLE_CLIENT_SECRET ||
    form.get("redirect_uri") !== FAKE_GOOGLE_REDIRECT_URI ||
    !bounded(code, 512) ||
    !/^[A-Za-z0-9._~-]{43,128}$/u.test(form.get("code_verifier") ?? "")
  )
    return reject(400);

  // No await occurs between lookup and deletion: consumption is atomic within this isolate.
  const record = codes.get(code);
  if (record === undefined) return json({ error: "invalid_grant" }, 400);
  codes.delete(code);
  stats.uniqueCodeExchanges += 1;
  const mode = configuration.token;
  configuration.token = "success";
  if (
    record.clientId !== form.get("client_id") ||
    record.redirectUri !== form.get("redirect_uri") ||
    (await digest(form.get("code_verifier") ?? "")) !== record.challenge
  )
    return json({ error: "invalid_grant" }, 400);
  if (mode === "rate_limited")
    return json({ error: "temporarily_unavailable" }, 429, { "retry-after": "2" });
  if (mode === "consume_then_fail") return json({ error: "server_error" }, 500);
  if (mode === "stall") {
    await new Promise((resolve) => setTimeout(resolve, 60_000));
    return json({ error: "stalled_request_was_not_cancelled" }, 500);
  }

  const now = Math.floor(Date.now() / 1_000);
  const calendar = record.scopes.includes(FAKE_CALENDAR_SCOPE);
  const issuer =
    mode === "wrong_issuer"
      ? "https://attacker.invalid"
      : mode === "alternate_issuer"
        ? "accounts.google.com"
        : CANONICAL_ISSUER;
  const audience = mode === "wrong_audience" ? "wrong-test-client" : FAKE_GOOGLE_CLIENT_ID;
  const payload: Record<string, unknown> = {
    iss: issuer,
    aud: audience,
    azp: mode === "wrong_azp" ? "wrong-test-client" : FAKE_GOOGLE_CLIENT_ID,
    sub: configuration.subject,
    email: configuration.email,
    name: "Fake Test User",
    email_verified: true,
    iat: mode === "expired" ? now - 7_200 : now - 5,
    exp: mode === "expired" ? now - 3_600 : now + 3_600,
    nonce: mode === "wrong_nonce" ? "wrong-test-nonce" : record.nonce,
  };
  const idToken = await sign(payload, mode === "wrong_signature");
  const response: Record<string, unknown> = {
    access_token: "fake-access-token-000000000000000000000001",
    expires_in: 3_600,
    token_type: "Bearer",
    id_token: idToken,
  };
  if (mode !== "omitted_scope")
    response["scope"] =
      mode === "writable_scope"
        ? `${record.scopes.join(" ")} https://www.googleapis.com/auth/calendar`
        : record.scopes.join(" ");
  if (calendar && mode !== "missing_refresh_token")
    response["refresh_token"] = "fake-refresh-token-000000000000000000001";
  return json(response);
}

async function revoke(request: Request): Promise<Response> {
  if (request.method !== "POST") return reject(405);
  const form = await strictForm(request, ["token"]);
  const value = form?.get("token") ?? "";
  if (!bounded(value, 16_384)) return reject(400);
  stats.revokeCalls += 1;
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

function calendar(request: Request, url: URL): Response {
  if (
    !configuration.calendarEnabled ||
    request.method !== "GET" ||
    !/^Bearer [\x21-\x7e]{1,16384}$/u.test(request.headers.get("authorization") ?? "")
  )
    return reject(request.method === "GET" ? 404 : 405);
  const list = url.pathname === "/calendar/v3/users/me/calendarList";
  const events = /^\/calendar\/v3\/calendars\/[^/]+\/events$/u.test(url.pathname);
  if (!list && !events) return reject(404);
  stats.calendarCalls += 1;
  const mode = configuration.calendar;
  configuration.calendar = "success";
  if (mode === "rate_limited")
    return json({ error: { errors: [{ reason: "rateLimitExceeded" }] } }, 429, {
      "retry-after": "3",
    });
  if (mode === "malformed") return json({ items: "not-an-array" });
  if (list)
    return json({
      items: [
        {
          id: "fake-calendar",
          summary: "Fake Calendar",
          accessRole: "reader",
          primary: true,
          selected: true,
        },
      ],
    });
  return json({ items: [] });
}

function validConfiguration(value: unknown): value is FakeGoogleConfiguration {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "authorization",
    "token",
    "calendar",
    "calendarEnabled",
    "subject",
    "email",
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key))) return false;
  const auth = ["success", "access_denied", "unknown_error"];
  const tokenModes: FakeTokenMode[] = [
    "success",
    "wrong_nonce",
    "wrong_issuer",
    "alternate_issuer",
    "wrong_audience",
    "wrong_azp",
    "wrong_signature",
    "expired",
    "omitted_scope",
    "writable_scope",
    "missing_refresh_token",
    "rate_limited",
    "stall",
    "consume_then_fail",
  ];
  const calendarModes: FakeCalendarMode[] = ["success", "rate_limited", "malformed"];
  return (
    (record["authorization"] === undefined || auth.includes(record["authorization"] as string)) &&
    (record["token"] === undefined || tokenModes.includes(record["token"] as FakeTokenMode)) &&
    (record["calendar"] === undefined ||
      calendarModes.includes(record["calendar"] as FakeCalendarMode)) &&
    (record["calendarEnabled"] === undefined || typeof record["calendarEnabled"] === "boolean") &&
    (record["subject"] === undefined ||
      (typeof record["subject"] === "string" && bounded(record["subject"], 255))) &&
    (record["email"] === undefined ||
      (typeof record["email"] === "string" && bounded(record["email"], 320)))
  );
}

async function control(request: Request, url: URL): Promise<Response> {
  if (url.pathname === "/reset" && request.method === "POST") {
    reset();
    return new Response(null, { status: 204 });
  }
  if (url.pathname === "/configure" && request.method === "POST") {
    let value: unknown;
    try {
      value = await request.json();
    } catch {
      return json({ error: "invalid_control_request" }, 400);
    }
    if (!validConfiguration(value)) return json({ error: "invalid_control_request" }, 400);
    configuration = { ...configuration, ...value };
    return new Response(null, { status: 204 });
  }
  if (url.pathname === "/stats" && request.method === "GET") return json(stats);
  return json({ error: "invalid_control_request" }, 404);
}

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin === CONTROL_ORIGIN) return control(request, url);
    if (url.origin !== FAKE_GOOGLE_ORIGIN) return reject(404);
    if (url.pathname === "/authorize") return authorize(request, url);
    if (url.pathname === "/token") return token(request);
    if (url.pathname === "/jwks") {
      if (request.method !== "GET" || url.search !== "")
        return reject(request.method === "GET" ? 400 : 405);
      return json({ keys: [FAKE_PUBLIC_JWK] }, 200, {
        "cache-control": "public, max-age=300",
        "content-security-policy": "default-src 'none'",
      });
    }
    if (url.pathname === "/revoke") return revoke(request);
    if (url.pathname.startsWith("/calendar/v3/")) return calendar(request, url);
    return reject(404);
  },
};
