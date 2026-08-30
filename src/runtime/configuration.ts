import { createRemoteJWKSet } from "jose";

import {
  exchangeGoogleCalendarCode,
  exchangeGoogleSignInCode,
  googleOidcProductionEndpoints,
  googleOidcTestEndpoints,
  type GoogleOidcClient,
} from "../auth/google-oidc";
import { DeviceSessions } from "../auth/device-sessions";
import { IdentityDeletion } from "../auth/identity-deletion";
import { OAuthTransactions } from "../auth/oauth-transactions";
import { decodeSecretKey, tokenKeyringFromEnvironment } from "../crypto/secret-keys";
import { webCryptoRandom } from "../crypto/random";
import type { KeyEncryptionKeyring } from "../crypto/token-envelope";
import type { Env } from "../env";
import {
  googleProductionConfiguration,
  googleTestConfiguration,
  revokeGoogleTokenBestEffort,
  type GoogleProviderConfiguration,
} from "../provider/google";

const CALLBACK_PATH = "/oauth/google/callback";
const GOOGLE_ISSUER = "https://accounts.google.com";
const PRODUCTION = {
  authorization: "https://accounts.google.com/o/oauth2/v2/auth",
  token: "https://oauth2.googleapis.com/token",
  jwks: "https://www.googleapis.com/oauth2/v3/certs",
  revocation: "https://oauth2.googleapis.com/revoke",
  calendar: "https://www.googleapis.com",
} as const;
const LOCAL = {
  authorization: "http://127.0.0.1:9797/authorize",
  token: "http://127.0.0.1:9797/token",
  jwks: "http://127.0.0.1:9797/jwks",
  revocation: "http://127.0.0.1:9797/revoke",
  calendar: "http://127.0.0.1:9797",
} as const;
const ENVIRONMENTS = new Set(["local", "lab", "staging", "production"]);

export interface RuntimeConfiguration {
  readonly environment: Env["ENVIRONMENT"];
  readonly deviceSessions: DeviceSessions;
  readonly identityDeletion: IdentityDeletion;
  readonly oauthTransactions: OAuthTransactions;
  readonly tokenKeyring: KeyEncryptionKeyring;
  readonly googleProvider: GoogleProviderConfiguration;
  readonly outboundFetch: typeof fetch;
}

const cache = new WeakMap<object, Promise<RuntimeConfiguration>>();

function exactOrigin(value: string, requireHttps: boolean): string {
  const url = new URL(value);
  if (
    (requireHttps
      ? url.protocol !== "https:"
      : url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    value !== url.origin
  ) {
    throw new TypeError("PUBLIC_ORIGIN must be an exact origin");
  }
  return url.origin;
}

function exact(value: string, expected: string, name: string): string {
  if (value !== expected) throw new TypeError(`${name} is not pinned`);
  return value;
}

function keyring(name: string, value: string): KeyEncryptionKeyring {
  return { activeVersion: 1, keys: new Map([[1, decodeSecretKey(name, value)]]) };
}

const outboundFetch: typeof fetch = async (input, init) => {
  const rejectRedirect = init?.redirect === "error";
  const response = await globalThis.fetch(
    input,
    rejectRedirect ? { ...init, redirect: "manual" } : init,
  );
  if (rejectRedirect && response.status >= 300 && response.status < 400) {
    throw new TypeError("outbound redirect rejected");
  }
  return response;
};

function initialize(env: Env): RuntimeConfiguration {
  if (!ENVIRONMENTS.has(env.ENVIRONMENT)) throw new TypeError("ENVIRONMENT is invalid");
  if (env.GOOGLE_ISSUER !== GOOGLE_ISSUER) throw new TypeError("GOOGLE_ISSUER is invalid");
  const local = env.ENVIRONMENT === "local";
  const publicOrigin = exactOrigin(env.PUBLIC_ORIGIN, !local);
  if (local && publicOrigin !== "http://127.0.0.1:8787") {
    throw new TypeError("local PUBLIC_ORIGIN is not pinned");
  }
  const selected = local ? LOCAL : PRODUCTION;

  exact(env.GOOGLE_AUTHORIZATION_ENDPOINT, selected.authorization, "authorization endpoint");
  exact(env.GOOGLE_TOKEN_ENDPOINT, selected.token, "token endpoint");
  exact(env.GOOGLE_JWKS_URI, selected.jwks, "JWKS endpoint");
  exact(env.GOOGLE_REVOCATION_ENDPOINT, selected.revocation, "revocation endpoint");
  exact(env.GOOGLE_CALENDAR_API_ORIGIN, selected.calendar, "Calendar API origin");
  if (env.GOOGLE_CLIENT_ID.length === 0 || env.GOOGLE_CLIENT_SECRET.length === 0)
    throw new TypeError("Google client configuration is invalid");

  const sessionPepper = decodeSecretKey("SESSION_PEPPER", env.SESSION_PEPPER);
  const identityFenceKey = decodeSecretKey("IDENTITY_FENCE_KEY", env.IDENTITY_FENCE_KEY);
  if (env.OAUTH_TRANSACTION_KEK_V1 === env.TOKEN_KEK_V1) {
    throw new TypeError("OAuth transaction and token KEKs must be distinct");
  }
  const transactionKeyring = keyring("OAUTH_TRANSACTION_KEK_V1", env.OAUTH_TRANSACTION_KEK_V1);
  const tokenKeyring = tokenKeyringFromEnvironment(env);
  // Decode future-slice keys now so readiness fails before serving with partial configuration.
  decodeSecretKey("CURSOR_KEY", env.CURSOR_KEY);
  decodeSecretKey("EVENT_ID_KEY_V1", env.EVENT_ID_KEY_V1);

  const oidcEndpoints = local
    ? googleOidcTestEndpoints({
        authorizationEndpoint: selected.authorization,
        tokenEndpoint: selected.token,
      })
    : googleOidcProductionEndpoints();
  const googleProvider = local
    ? googleTestConfiguration({
        tokenEndpoint: selected.token,
        revocationEndpoint: selected.revocation,
        calendarApiOrigin: selected.calendar,
      })
    : googleProductionConfiguration();
  const client: GoogleOidcClient = {
    clientId: env.GOOGLE_CLIENT_ID,
    clientSecret: env.GOOGLE_CLIENT_SECRET,
    redirectUri: `${publicOrigin}${CALLBACK_PATH}`,
  };
  const keyResolver = createRemoteJWKSet(new URL(selected.jwks), { timeoutDuration: 5_000 });
  const nowEpochSeconds = (): number => Math.floor(Date.now() / 1_000);
  const deviceSessions = new DeviceSessions({
    db: env.DB,
    pepper: sessionPepper,
    clock: { now: () => new Date() },
    random: webCryptoRandom,
  });
  const identityDeletion = new IdentityDeletion({
    db: env.DB,
    hmacKey: identityFenceKey,
    nowEpochSeconds,
  });
  const oidcDependencies = {
    fetch: outboundFetch,
    keyResolver,
    nowEpochSeconds,
    timeoutMilliseconds: 5_000,
  } as const;
  const oauthTransactions = new OAuthTransactions({
    db: env.DB,
    environment: env.ENVIRONMENT,
    nowEpochSeconds,
    random: webCryptoRandom,
    uuid: () => crypto.randomUUID(),
    transactionKeyring,
    tokenKeyring,
    identityDeletion,
    deviceSessions,
    google: {
      endpoints: oidcEndpoints,
      client,
      exchangeSignIn: (input) =>
        exchangeGoogleSignInCode(oidcEndpoints, client, input, oidcDependencies),
      exchangeCalendar: (input) =>
        exchangeGoogleCalendarCode(oidcEndpoints, client, input, oidcDependencies),
      revokeCalendarToken: (token) =>
        revokeGoogleTokenBestEffort({
          configuration: googleProvider,
          token,
          fetch: outboundFetch,
          timeoutMs: 5_000,
        }),
    },
  });
  return Object.freeze({
    environment: env.ENVIRONMENT,
    deviceSessions,
    identityDeletion,
    oauthTransactions,
    tokenKeyring,
    googleProvider,
    outboundFetch,
  });
}

export function runtimeConfiguration(env: Env): Promise<RuntimeConfiguration> {
  let configured = cache.get(env);
  if (configured === undefined) {
    configured = Promise.resolve().then(() => initialize(env));
    cache.set(env, configured);
  }
  return configured;
}
