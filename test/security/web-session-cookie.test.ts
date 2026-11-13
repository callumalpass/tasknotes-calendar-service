import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createWorker } from "../../src/index";
import type { Env } from "../../src/env";
import type { FakeGoogleConfiguration } from "../support/fake-google";

const WEB_ORIGIN = "https://app.tasknotes.test";
const COOKIE = "__Host-tasknotes_session";
const verifier = "web-cookie-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher };
const configured: Env = { ...bindings, ALLOWED_ORIGINS: WEB_ORIGIN };
const fake = bindings.FAKE_GOOGLE;
const worker = createWorker();

interface Started {
  transaction_id: string;
  authorization_url: string;
  polling_secret: string;
}

async function send(path: string, init: RequestInit = {}): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(
    new Request(`http://127.0.0.1:8787${path}`, init),
    configured,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

function post(path: string, value: unknown, origin: string | null = WEB_ORIGIN): Promise<Response> {
  return send(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(origin === null ? {} : { origin }),
    },
    body: JSON.stringify(value),
  });
}

function withCookie(credential: string, origin: string | null = WEB_ORIGIN): Headers {
  const headers = new Headers({ cookie: `${COOKIE}=${credential}` });
  if (origin !== null) headers.set("origin", origin);
  return headers;
}

async function configureGoogle(value: FakeGoogleConfiguration): Promise<void> {
  const response = await fake.fetch("https://fake-google-control.test/configure", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(value),
  });
  expect(response.status).toBe(204);
}

async function authorized(
  clientKind: "web" | "obsidian",
  subject: string,
): Promise<{ path: string; request: Record<string, string> }> {
  await configureGoogle({ subject, email: "cookie@example.test" });
  const code_challenge = btoa(
    String.fromCharCode(
      ...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    ),
  )
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
  const startResponse = await post("/v1/sign-in/start", {
    client_kind: clientKind,
    device_name: "Cookie browser",
    code_challenge,
  });
  expect(startResponse.status).toBe(201);
  const started = await startResponse.json<Started>();
  const redirect = await fake.fetch(new Request(started.authorization_url, { redirect: "manual" }));
  const location = new URL(redirect.headers.get("location") ?? "missing:");
  const callback = await send(`${location.pathname}${location.search}`);
  expect(callback.status).toBe(200);
  const confirmation_code = /class="code"[^>]*>([23456789A-HJ-NP-Z]{8})</u.exec(
    await callback.text(),
  )?.[1];
  expect(confirmation_code).toBeDefined();
  return {
    path: `/v1/sign-in/${started.transaction_id}/redeem`,
    request: {
      polling_secret: started.polling_secret,
      code_verifier: verifier,
      confirmation_code: confirmation_code ?? "",
    },
  };
}

function credentialFrom(response: Response): string {
  const value = new RegExp(`^${COOKIE}=([^;]+);`, "u").exec(
    response.headers.get("set-cookie") ?? "",
  )?.[1];
  expect(value).toBeDefined();
  return value ?? "";
}

async function signIn(subject: string): Promise<{ credential: string; sessionId: string }> {
  const { path, request } = await authorized("web", subject);
  const response = await post(path, request);
  expect(response.status).toBe(200);
  const body = await response.json<{ session: { session_id: string } }>();
  return { credential: credentialFrom(response), sessionId: body.session.session_id };
}

beforeEach(async () => {
  expect(
    (await fake.fetch("https://fake-google-control.test/reset", { method: "POST" })).status,
  ).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

describe("web session cookie", () => {
  it("delivers the credential only in a strict host-only cookie", async () => {
    const output = vi.spyOn(console, "log");
    const errors = vi.spyOn(console, "error");
    const { path, request } = await authorized("web", "cookie-delivery");
    const response = await post(path, request);
    expect(response.status).toBe(200);
    const text = await response.text();
    const credential = credentialFrom(response);
    expect(text).not.toContain(credential);
    expect(Object.keys((JSON.parse(text) as { session: object }).session).sort()).toEqual([
      "idle_expires_at",
      "session_id",
    ]);
    expect(response.headers.get("set-cookie")).toBe(
      `${COOKIE}=${credential}; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Strict`,
    );
    expect(response.headers.get("access-control-allow-credentials")).toBe("true");
    expect((await send("/v1/session", { headers: withCookie(credential) })).status).toBe(200);
    const logged = JSON.stringify([...output.mock.calls, ...errors.mock.calls]);
    expect(logged).not.toContain(credential);
    output.mockRestore();
    errors.mockRestore();
  });

  it("keeps bearer delivery and rejects the cookie for other client kinds", async () => {
    const { path, request } = await authorized("obsidian", "cookie-bearer");
    const response = await post(path, request, null);
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toBeNull();
    const { session } = await response.json<{ session: { credential: string } }>();
    const bearer = new Headers({ authorization: `Bearer ${session.credential}` });
    expect((await send("/v1/session", { headers: bearer })).status).toBe(200);
    expect((await send("/v1/session", { headers: withCookie(session.credential) })).status).toBe(
      401,
    );
  });

  it("rejects a web session presented as a bearer credential", async () => {
    const { credential } = await signIn("cookie-as-bearer");
    const headers = new Headers({
      authorization: `Bearer ${credential}`,
      origin: WEB_ORIGIN,
    });
    expect((await send("/v1/session", { headers })).status).toBe(401);
  });

  it.each([null, "null", "https://app.tasknotes.test.attacker.test", "https://attacker.test"])(
    "refuses a valid cookie with origin %s",
    async (origin) => {
      const { credential, sessionId } = await signIn(`cookie-origin-${String(origin)}`);
      const headers = withCookie(credential, origin);
      expect((await send("/v1/session", { headers })).status).toBe(403);
      expect((await send(`/v1/devices/${sessionId}`, { method: "DELETE", headers })).status).toBe(
        403,
      );
      expect((await send("/v1/account", { method: "DELETE", headers })).status).toBe(403);
      expect((await send("/v1/session", { headers: withCookie(credential) })).status).toBe(200);
    },
  );

  it("rejects a smuggled second session cookie", async () => {
    const { credential } = await signIn("cookie-duplicate");
    const headers = withCookie(credential);
    headers.set("cookie", `${COOKIE}=${credential}; other=1; ${COOKIE}=${credential}`);
    expect((await send("/v1/session", { headers })).status).toBe(401);
  });

  it("does not let an Authorization header fall back to the cookie", async () => {
    const { credential } = await signIn("cookie-no-fallback");
    const headers = withCookie(credential);
    headers.set("authorization", "Bearer not-a-credential");
    expect((await send("/v1/session", { headers })).status).toBe(401);
  });

  it("refuses a web redeem from an unlisted origin without consuming it", async () => {
    const { path, request } = await authorized("web", "cookie-redeem-origin");
    for (const origin of [null, "https://attacker.test"]) {
      const refused = await post(path, request, origin);
      expect(refused.status).toBe(409);
      expect(refused.headers.get("set-cookie")).toBeNull();
    }
    expect((await post(path, request)).status).toBe(200);
  });

  it("issues exactly one cookie across concurrent redeems", async () => {
    const { path, request } = await authorized("web", "cookie-replay");
    const responses = await Promise.all(Array.from({ length: 8 }, () => post(path, request)));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    expect(responses.filter((response) => response.headers.has("set-cookie"))).toHaveLength(1);
    expect((await post(path, request)).headers.has("set-cookie")).toBe(false);
  });

  it("issues the cookie again only when a use begins the idle period again", async () => {
    const { credential, sessionId } = await signIn("cookie-renewal");
    const headers = withCookie(credential);
    const fresh = await send("/v1/session", { headers });
    expect(fresh.status).toBe(200);
    expect(fresh.headers.get("set-cookie")).toBeNull();

    await bindings.DB.prepare(
      `UPDATE device_sessions
       SET created_at = created_at - 3600, last_used_at = last_used_at - 3600,
           idle_expires_at = unixepoch() + 60,
           absolute_expires_at = unixepoch() + 60
       WHERE id = ?`,
    )
      .bind(sessionId)
      .run();
    const renewed = await send("/v1/session", { headers });
    expect(renewed.status).toBe(200);
    expect(renewed.headers.get("set-cookie")).toBe(
      `${COOKIE}=${credential}; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Strict`,
    );
    const body = await renewed.json<{ idle_expires_at: string }>();
    expect(Date.parse(body.idle_expires_at) - Date.now()).toBeGreaterThan(29 * 24 * 3_600_000);
    expect((await send("/v1/session", { headers })).headers.get("set-cookie")).toBeNull();

    // A response without a body renews as well.
    await bindings.DB.prepare(
      `UPDATE device_sessions
       SET created_at = created_at - 3600, last_used_at = last_used_at - 3600 WHERE id = ?`,
    )
      .bind(sessionId)
      .run();
    const other = await signIn("cookie-renewal");
    const revoked = await send(`/v1/devices/${other.sessionId}`, { method: "DELETE", headers });
    expect(revoked.status).toBe(204);
    expect(revoked.headers.get("set-cookie")).toContain("Max-Age=2592000");
  });

  it("never sets a cookie when a bearer session renews", async () => {
    const { path, request } = await authorized("obsidian", "cookie-bearer-renewal");
    const response = await post(path, request, null);
    const { session } = await response.json<{
      session: { credential: string; session_id: string };
    }>();
    await bindings.DB.prepare(
      `UPDATE device_sessions
       SET created_at = created_at - 3600, last_used_at = last_used_at - 3600 WHERE id = ?`,
    )
      .bind(session.session_id)
      .run();
    const used = await send("/v1/session", {
      headers: { authorization: `Bearer ${session.credential}` },
    });
    expect(used.status).toBe(200);
    expect(used.headers.get("set-cookie")).toBeNull();
  });

  it("clears the cookie and revokes when signing out this session", async () => {
    const { credential, sessionId } = await signIn("cookie-sign-out");
    const headers = withCookie(credential);
    const response = await send(`/v1/devices/${sessionId}`, { method: "DELETE", headers });
    expect(response.status).toBe(204);
    expect(response.headers.get("set-cookie")).toBe(
      `${COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict`,
    );
    expect((await send("/v1/session", { headers })).status).toBe(401);
  });

  it("keeps the cookie when revoking another device, and blocks other tenants", async () => {
    const owner = await signIn("cookie-owner");
    const second = await signIn("cookie-owner");
    const other = await signIn("cookie-other");
    const denied = await send(`/v1/devices/${second.sessionId}`, {
      method: "DELETE",
      headers: withCookie(other.credential),
    });
    expect(denied.status).toBe(404);
    expect(denied.headers.get("set-cookie")).toBeNull();
    const revoked = await send(`/v1/devices/${second.sessionId}`, {
      method: "DELETE",
      headers: withCookie(owner.credential),
    });
    expect(revoked.status).toBe(204);
    expect(revoked.headers.get("set-cookie")).toBeNull();
    expect((await send("/v1/session", { headers: withCookie(second.credential) })).status).toBe(
      401,
    );
    expect((await send("/v1/session", { headers: withCookie(owner.credential) })).status).toBe(200);
  });

  it("clears the cookie on account deletion, which dominates the session", async () => {
    const { credential } = await signIn("cookie-delete");
    const headers = withCookie(credential);
    const response = await send("/v1/account", { method: "DELETE", headers });
    expect(response.status).toBe(204);
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
    expect((await send("/v1/session", { headers })).status).toBe(401);
  });
});
