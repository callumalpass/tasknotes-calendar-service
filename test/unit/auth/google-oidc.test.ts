import { SignJWT, generateKeyPair } from "jose";
import type { CryptoKey, JWTVerifyGetKey, JWTPayload } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";

import {
  GoogleOidcError,
  createGoogleCalendarAuthorizationUrl,
  createGoogleSignInAuthorizationUrl,
  exchangeGoogleCalendarCode,
  exchangeGoogleSignInCode,
  googleOidcProductionEndpoints,
  googleOidcTestEndpoints,
} from "../../../src/auth/google-oidc";
import type {
  GoogleOidcClient,
  GoogleOidcDependencies,
  GoogleOidcEndpoints,
  GoogleTokenExchangeInput,
} from "../../../src/auth/google-oidc";

const NOW = 2_000_000_000;
const KID = "fixture-key-1";
const NONCE = "transaction-nonce";
const NONCE_HASH = "cOkxTHbZOikKdhfVbLdzHLLr4ubBUOTkYe3fZa_sxN4";
const CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";
const endpoints: GoogleOidcEndpoints = googleOidcTestEndpoints({
  authorizationEndpoint: "http://127.0.0.1:9797/authorize",
  tokenEndpoint: "http://127.0.0.1:9797/token",
});
const client: GoogleOidcClient = {
  clientId: "tasknotes-client.apps.googleusercontent.com",
  clientSecret: "client-secret",
  redirectUri: "http://127.0.0.1:8787/oauth/google/callback",
};
const exchangeInput: GoogleTokenExchangeInput = {
  code: "one-time-code",
  codeVerifier: "a".repeat(64),
  expectedNonceHash: NONCE_HASH,
};

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let otherPrivateKey: CryptoKey;

beforeAll(async () => {
  ({ privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true }));
  ({ privateKey: otherPrivateKey } = await generateKeyPair("RS256", { extractable: true }));
});

function claims(overrides: Partial<JWTPayload> = {}): JWTPayload {
  return {
    iss: "https://accounts.google.com",
    sub: "google-subject-123",
    aud: client.clientId,
    nonce: NONCE,
    iat: NOW - 10,
    exp: NOW + 3_590,
    email: "display@example.test",
    email_verified: true,
    name: "Display Name",
    ...overrides,
  };
}

async function signedToken(
  payload: JWTPayload = claims(),
  options: { kid?: string; key?: CryptoKey; alg?: string } = {},
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: options.alg ?? "RS256", kid: options.kid ?? KID })
    .sign(options.key ?? privateKey);
}

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value), { status: init.status ?? 200, headers });
}

async function tokenPayload(
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  return {
    access_token: "access-secret",
    expires_in: 3_600,
    token_type: "Bearer",
    scope: "openid email profile",
    id_token: await signedToken(),
    ...overrides,
  };
}

async function calendarTokenPayload(
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  return tokenPayload({
    refresh_token: "refresh-secret",
    scope: `openid email profile ${CALENDAR_SCOPE}`,
    ...overrides,
  });
}

function resolver(
  keys: ReadonlyMap<string, CryptoKey> = new Map([[KID, publicKey]]),
): JWTVerifyGetKey {
  return (header) => {
    if (typeof header.kid !== "string") return Promise.reject(new Error("unknown signing key"));
    const key = keys.get(header.kid);
    if (key === undefined) return Promise.reject(new Error("unknown signing key"));
    return Promise.resolve(key);
  };
}

function dependencies(response: Response): GoogleOidcDependencies {
  return {
    fetch: vi.fn(() => Promise.resolve(response)),
    keyResolver: resolver(),
    nowEpochSeconds: () => NOW,
    timeoutMilliseconds: 1_000,
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: "GoogleOidcError",
    message: "Google authorization could not be completed",
    code,
  });
}

function mutateSignature(token: string): string {
  const segments = token.split(".");
  const signature = segments[2];
  if (segments.length !== 3 || signature === undefined || signature.length === 0) {
    throw new Error("fixture is not a compact JWT");
  }
  const changed = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
  return `${segments[0]}.${segments[1]}.${changed}`;
}

describe("Google authorization URLs", () => {
  const authorization = {
    state: "supplied-state",
    nonce: "supplied-nonce",
    codeChallenge: "A".repeat(43),
  };

  it("constructs identity-only sign-in without offline or consent parameters", () => {
    const url = createGoogleSignInAuthorizationUrl(endpoints, client, authorization);
    expect(url.origin + url.pathname).toBe(endpoints.authorizationEndpoint);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state: authorization.state,
      nonce: authorization.nonce,
      code_challenge: authorization.codeChallenge,
      code_challenge_method: "S256",
    });
    expect(url.searchParams.has("access_type")).toBe(false);
    expect(url.searchParams.has("prompt")).toBe(false);
  });

  it("constructs explicit calendar consent with identity, read-only, and offline parameters", () => {
    const url = createGoogleCalendarAuthorizationUrl(endpoints, client, {
      ...authorization,
      calendarScopes: [CALENDAR_SCOPE],
    });
    expect(url.searchParams.get("scope")).toBe(`openid email profile ${CALENDAR_SCOPE}`);
    expect(url.searchParams.get("access_type")).toBe("offline");
    expect(url.searchParams.has("include_granted_scopes")).toBe(false);
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("redirect_uri")).toBe(client.redirectUri);
  });

  it("pins production endpoints and permits only explicit loopback test endpoints", () => {
    expect(googleOidcProductionEndpoints()).toMatchObject({
      authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      mode: "production",
    });
    expect(() =>
      googleOidcTestEndpoints({
        authorizationEndpoint: "https://evil.example/authorize",
        tokenEndpoint: "http://127.0.0.1:9797/token",
      }),
    ).toThrow("exact loopback URL");
    expect(() =>
      createGoogleSignInAuthorizationUrl(
        endpoints,
        { ...client, redirectUri: "https://evil.example/oauth/google/callback" },
        authorization,
      ),
    ).toThrow(GoogleOidcError);
  });

  it("rejects writable, duplicate, and malformed authorization inputs", () => {
    expect(() =>
      createGoogleCalendarAuthorizationUrl(endpoints, client, {
        ...authorization,
        calendarScopes: ["https://www.googleapis.com/auth/calendar"],
      }),
    ).toThrow(GoogleOidcError);
    expect(() =>
      createGoogleCalendarAuthorizationUrl(endpoints, client, {
        ...authorization,
        calendarScopes: [CALENDAR_SCOPE, CALENDAR_SCOPE],
      }),
    ).toThrow(GoogleOidcError);
    expect(() =>
      createGoogleSignInAuthorizationUrl(endpoints, client, {
        ...authorization,
        codeChallenge: "short",
      }),
    ).toThrow(GoogleOidcError);
  });
});

describe("Google code exchange and ID token verification", () => {
  it("posts the exact redirect URI and provider PKCE and returns identity only for sign-in", async () => {
    const response = jsonResponse(await tokenPayload());
    const deps = dependencies(response);
    const result = await exchangeGoogleSignInCode(endpoints, client, exchangeInput, deps);
    expect(result).toEqual({
      issuer: "https://accounts.google.com",
      subject: "google-subject-123",
      email: "display@example.test",
      emailVerified: true,
      name: "Display Name",
    });
    expect(result).not.toHaveProperty("tokenMaterial");
    const fetchMock = vi.mocked(deps.fetch);
    const [, init] = fetchMock.mock.calls[0] ?? [];
    const body = init?.body as URLSearchParams;
    expect(body.get("redirect_uri")).toBe(client.redirectUri);
    expect(body.get("code_verifier")).toBe(exchangeInput.codeVerifier);
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(init?.redirect).toBe("error");
  });

  it("rejects sign-in when any requested identity scope is missing", async () => {
    const response = jsonResponse(await tokenPayload({ scope: "openid email" }));

    await expectCode(
      exchangeGoogleSignInCode(endpoints, client, exchangeInput, dependencies(response)),
      "insufficient_scope",
    );
  });

  it("accepts Google's canonical identity-scope aliases without a refresh token", async () => {
    const response = jsonResponse(
      await tokenPayload({
        scope:
          "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
      }),
    );

    await expect(
      exchangeGoogleSignInCode(endpoints, client, exchangeInput, dependencies(response)),
    ).resolves.toMatchObject({ subject: "google-subject-123" });
  });

  it("accepts and canonicalizes Google's bare issuer spelling", async () => {
    const response = jsonResponse(
      await tokenPayload({ id_token: await signedToken(claims({ iss: "accounts.google.com" })) }),
    );
    await expect(
      exchangeGoogleSignInCode(endpoints, client, exchangeInput, dependencies(response)),
    ).resolves.toMatchObject({
      issuer: "https://accounts.google.com",
      subject: "google-subject-123",
    });
  });

  it.each([
    ["wrong issuer", { iss: "https://evil.example" }],
    ["wrong audience", { aud: "other-client" }],
    ["wrong authorized party", { aud: [client.clientId, "other-client"], azp: "other-client" }],
    ["missing authorized party for multiple audiences", { aud: [client.clientId, "other-client"] }],
    ["wrong nonce", { nonce: "other-nonce" }],
    ["expired token", { exp: NOW - 61 }],
    ["future issued-at", { iat: NOW + 61, exp: NOW + 3_600 }],
    ["stale issued-at", { iat: NOW - 3_662 }],
    ["future not-before", { nbf: NOW + 61 }],
    ["empty subject", { sub: "" }],
    ["oversized ASCII subject", { sub: "x".repeat(256) }],
    ["oversized UTF-8 subject", { sub: "é".repeat(128) }],
    ["C0 control in subject", { sub: "line\nbreak" }],
    ["DEL control in subject", { sub: "delete\u007fcontrol" }],
  ])("rejects %s", async (_label, override) => {
    const response = jsonResponse(
      await tokenPayload({ id_token: await signedToken(claims(override)) }),
    );
    await expectCode(
      exchangeGoogleSignInCode(endpoints, client, exchangeInput, dependencies(response)),
      "invalid_id_token",
    );
  });

  it("rejects a replayed nonce digest from another transaction", async () => {
    await expectCode(
      exchangeGoogleSignInCode(
        endpoints,
        client,
        {
          ...exchangeInput,
          expectedNonceHash: "2QVIx5mr1AYSE5odZn04x_kkSz642jhx9tjuwxNRrNc",
        },
        dependencies(jsonResponse(await tokenPayload())),
      ),
      "invalid_id_token",
    );
  });

  it.each(["", "not-base64url!", "A".repeat(42), "A".repeat(44), `${NONCE_HASH}=`])(
    "rejects a malformed expected nonce digest before provider exchange: %s",
    async (digest) => {
      const deps = dependencies(jsonResponse(await tokenPayload()));
      await expectCode(
        exchangeGoogleSignInCode(
          endpoints,
          client,
          { ...exchangeInput, expectedNonceHash: digest },
          deps,
        ),
        "invalid_request",
      );
      expect(deps.fetch).not.toHaveBeenCalled();
    },
  );

  it("accepts a multi-audience token only with the exact authorized party", async () => {
    const idToken = await signedToken(
      claims({ aud: [client.clientId, "other-client"], azp: client.clientId }),
    );
    await expect(
      exchangeGoogleSignInCode(
        endpoints,
        client,
        exchangeInput,
        dependencies(jsonResponse(await tokenPayload({ id_token: idToken }))),
      ),
    ).resolves.toMatchObject({ subject: "google-subject-123" });
  });

  it("rejects a non-RS256 algorithm, absent kid, unknown kid, and invalid signature", async () => {
    const valid = await signedToken();
    const segments = valid.split(".");
    const algorithmHeader = btoa(JSON.stringify({ alg: "HS256", kid: KID }))
      .replaceAll("=", "")
      .replaceAll("+", "-")
      .replaceAll("/", "_");
    const noKidHeader = btoa(JSON.stringify({ alg: "RS256" }))
      .replaceAll("=", "")
      .replaceAll("+", "-")
      .replaceAll("/", "_");
    const cases = [
      `${algorithmHeader}.${segments[1]}.${segments[2]}`,
      `${noKidHeader}.${segments[1]}.${segments[2]}`,
      await signedToken(claims(), { kid: "unknown-key" }),
      await signedToken(claims(), { key: otherPrivateKey }),
      mutateSignature(valid),
    ];
    for (const idToken of cases) {
      await expectCode(
        exchangeGoogleSignInCode(
          endpoints,
          client,
          exchangeInput,
          dependencies(jsonResponse(await tokenPayload({ id_token: idToken }))),
        ),
        "invalid_id_token",
      );
    }
  });

  it("rejects provider errors without exposing provider details", async () => {
    const deps = dependencies(
      jsonResponse({ error: "invalid_grant", error_description: "secret detail" }, { status: 400 }),
    );
    const rejection = exchangeGoogleSignInCode(endpoints, client, exchangeInput, deps);
    await expectCode(rejection, "provider_exchange_failed");
    await rejection.catch((error: unknown) => {
      expect(String(error)).not.toContain("invalid_grant");
      expect(String(error)).not.toContain("secret detail");
    });
  });

  it("rejects network failures, wrong content type, oversized bodies, and malformed JSON generically", async () => {
    const network: GoogleOidcDependencies = {
      ...dependencies(jsonResponse({})),
      fetch: vi.fn(async () => Promise.reject(new Error("raw network secret"))),
    };
    await expectCode(
      exchangeGoogleSignInCode(endpoints, client, exchangeInput, network),
      "provider_exchange_failed",
    );
    const responses = [
      new Response("{}", { headers: { "content-type": "text/plain" } }),
      new Response("{", { headers: { "content-type": "application/json" } }),
      new Response("x", {
        headers: { "content-type": "application/json", "content-length": "65537" },
      }),
    ];
    for (const response of responses) {
      await expectCode(
        exchangeGoogleSignInCode(endpoints, client, exchangeInput, dependencies(response)),
        "invalid_token_response",
      );
    }
  });
});

describe("calendar connection exchange", () => {
  it("returns bounded token material after subject and exact required-scope verification", async () => {
    const result = await exchangeGoogleCalendarCode(
      endpoints,
      client,
      {
        ...exchangeInput,
        expectedSubject: "google-subject-123",
        requiredCalendarScopes: [CALENDAR_SCOPE],
      },
      dependencies(jsonResponse(await calendarTokenPayload())),
    );
    expect(result.tokenMaterial).toEqual({
      accessToken: "access-secret",
      refreshToken: "refresh-secret",
      expiresInSeconds: 3_600,
      scopes: ["openid", "email", "profile", CALENDAR_SCOPE],
    });
  });

  it.each(["", "x".repeat(256), "é".repeat(128), "line\nbreak", "delete\u007fcontrol"])(
    "rejects an invalid expected subject before provider exchange: %s",
    async (expectedSubject) => {
      const deps = dependencies(jsonResponse(await calendarTokenPayload()));
      await expectCode(
        exchangeGoogleCalendarCode(
          endpoints,
          client,
          { ...exchangeInput, expectedSubject, requiredCalendarScopes: [CALENDAR_SCOPE] },
          deps,
        ),
        "invalid_request",
      );
      expect(deps.fetch).not.toHaveBeenCalled();
    },
  );

  it("rejects a different immutable subject", async () => {
    await expectCode(
      exchangeGoogleCalendarCode(
        endpoints,
        client,
        {
          ...exchangeInput,
          expectedSubject: "different-subject",
          requiredCalendarScopes: [CALENDAR_SCOPE],
        },
        dependencies(jsonResponse(await calendarTokenPayload())),
      ),
      "identity_mismatch",
    );
  });

  it("rejects a missing refresh token", async () => {
    const payload = await calendarTokenPayload();
    delete payload["refresh_token"];
    await expectCode(
      exchangeGoogleCalendarCode(
        endpoints,
        client,
        {
          ...exchangeInput,
          expectedSubject: "google-subject-123",
          requiredCalendarScopes: [CALENDAR_SCOPE],
        },
        dependencies(jsonResponse(payload)),
      ),
      "invalid_token_response",
    );
  });

  it("normalizes mixed identity aliases and rejects an inherited writable scope", async () => {
    const aliased = await exchangeGoogleCalendarCode(
      endpoints,
      client,
      {
        ...exchangeInput,
        expectedSubject: "google-subject-123",
        requiredCalendarScopes: [CALENDAR_SCOPE],
      },
      dependencies(
        jsonResponse(
          await calendarTokenPayload({
            scope: `openid email https://www.googleapis.com/auth/userinfo.email profile https://www.googleapis.com/auth/userinfo.profile ${CALENDAR_SCOPE}`,
          }),
        ),
      ),
    );
    expect(aliased.tokenMaterial.scopes).toEqual(["openid", "email", "profile", CALENDAR_SCOPE]);

    await expectCode(
      exchangeGoogleCalendarCode(
        endpoints,
        client,
        {
          ...exchangeInput,
          expectedSubject: "google-subject-123",
          requiredCalendarScopes: [CALENDAR_SCOPE],
        },
        dependencies(
          jsonResponse(
            await calendarTokenPayload({
              scope: `openid email profile ${CALENDAR_SCOPE} https://www.googleapis.com/auth/calendar.events`,
            }),
          ),
        ),
      ),
      "insufficient_scope",
    );
  });

  it.each([
    "openid email profile",
    `openid email ${CALENDAR_SCOPE}`,
    `openid email profile ${CALENDAR_SCOPE.slice(0, -1)}`,
  ])("rejects missing or merely prefix-matching granted scopes: %s", async (scope) => {
    await expectCode(
      exchangeGoogleCalendarCode(
        endpoints,
        client,
        {
          ...exchangeInput,
          expectedSubject: "google-subject-123",
          requiredCalendarScopes: [CALENDAR_SCOPE],
        },
        dependencies(jsonResponse(await calendarTokenPayload({ scope }))),
      ),
      "insufficient_scope",
    );
  });
});
