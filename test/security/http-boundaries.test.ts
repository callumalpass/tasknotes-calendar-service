import { env, exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";

import type { Env } from "../../src/env";
import type { FakeGoogleConfiguration, FakeGoogleStats } from "../support/fake-google";

const bindings = env as unknown as Env & { FAKE_GOOGLE: Fetcher };
const fake = bindings.FAKE_GOOGLE;
const verifier = "security-http-verifier-abcdefghijklmnopqrstuvwxyz0123456789";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function challenge(): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
}

async function api(path: string, init: RequestInit = {}, credential?: string): Promise<Response> {
  const headers = new Headers(init.headers);
  if (credential !== undefined) headers.set("authorization", `Bearer ${credential}`);
  return exports.default.fetch(new Request(`http://127.0.0.1:8787${path}`, { ...init, headers }));
}

async function post(path: string, value: unknown, credential?: string): Promise<Response> {
  return api(
    path,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    },
    credential,
  );
}

async function control(path: string, init?: RequestInit): Promise<Response> {
  return fake.fetch(`https://fake-google-control.test${path}`, init);
}

async function configure(value: FakeGoogleConfiguration): Promise<void> {
  expect(
    await control("/configure", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    }),
  ).toHaveProperty("status", 204);
}

async function statistics(): Promise<FakeGoogleStats> {
  return (await control("/stats")).json<FakeGoogleStats>();
}

interface Started {
  transaction_id: string;
  authorization_url: string;
  polling_secret: string;
}

async function start(path: string, credential?: string): Promise<Started> {
  const response = await post(
    path,
    { client_kind: "web", device_name: "Security browser", code_challenge: await challenge() },
    credential,
  );
  expect(response.status).toBe(201);
  return response.json<Started>();
}

async function authorize(started: Started): Promise<URL> {
  const response = await fake.fetch(new Request(started.authorization_url, { redirect: "manual" }));
  expect(response.status).toBe(302);
  return new URL(response.headers.get("location") ?? "missing:");
}

async function signIn(subject: string): Promise<{ credential: string; sessionId: string }> {
  await configure({ subject, email: "same-security@example.test" });
  const started = await start("/v1/sign-in/start");
  expect((await exports.default.fetch(new Request(await authorize(started)))).status).toBe(200);
  const response = await post(`/v1/sign-in/${started.transaction_id}/redeem`, {
    polling_secret: started.polling_secret,
    code_verifier: verifier,
  });
  expect(response.status).toBe(200);
  const value = await response.json<{ session: { credential: string; session_id: string } }>();
  return { credential: value.session.credential, sessionId: value.session.session_id };
}

async function connect(credential: string): Promise<{ id: string; started: Started }> {
  const started = await start("/v1/connections/google/start", credential);
  expect((await exports.default.fetch(new Request(await authorize(started)))).status).toBe(200);
  const response = await post(
    `/v1/connections/google/${started.transaction_id}/redeem`,
    { polling_secret: started.polling_secret, code_verifier: verifier },
    credential,
  );
  expect(response.status).toBe(200);
  return { id: (await response.json<{ connection_id: string }>()).connection_id, started };
}

beforeEach(async () => {
  expect((await control("/reset", { method: "POST" })).status).toBe(204);
  await bindings.DB.batch([
    bindings.DB.prepare("DELETE FROM oauth_transactions"),
    bindings.DB.prepare("DELETE FROM principals"),
    bindings.DB.prepare("DELETE FROM identity_deletion_fences"),
  ]);
});

describe("Worker HTTP security boundaries", () => {
  it("pins callback origin and exact path before consuming provider authority", async () => {
    const started = await start("/v1/sign-in/start");
    const callback = await authorize(started);
    const hostile = [
      new URL(callback.href.replace("http://127.0.0.1:8787", "http://attacker.test")),
      new URL(callback.href.replace(":8787", ":8788")),
      new URL(callback.href.replace("http://", "https://")),
      new URL(callback.href.replace("/oauth/google/callback", "/oauth/google/callback/")),
    ];
    const duplicate = new URL(callback);
    duplicate.searchParams.append("state", callback.searchParams.get("state") ?? "");
    const unknown = new URL(callback);
    unknown.searchParams.set("unrelated", "private-value");

    for (const url of hostile) {
      const response = await exports.default.fetch(new Request(url));
      expect(response.status).toBe(404);
    }
    for (const url of [duplicate, unknown]) {
      const response = await exports.default.fetch(new Request(url));
      expect(response.status).toBe(400);
    }
    expect(await statistics()).toMatchObject({ tokenRequests: 0, uniqueCodeExchanges: 0 });

    expect((await exports.default.fetch(new Request(callback))).status).toBe(200);
    expect(await statistics()).toMatchObject({ tokenRequests: 1, uniqueCodeExchanges: 1 });
  });

  it("fences local disconnect despite corrupt token custody under concurrency", async () => {
    const owner = await signIn("disconnect-owner");
    const connection = await connect(owner.credential);
    const validationTrigger = await bindings.DB.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'connections_validate_update'",
    ).first<{ sql: string }>();
    if (validationTrigger === null) throw new Error("expected connection validation trigger");
    await bindings.DB.prepare("DROP TRIGGER connections_validate_update").run();
    await bindings.DB.prepare("UPDATE connections SET ciphertext = 'corrupt' WHERE id = ?")
      .bind(connection.id)
      .run();
    await bindings.DB.prepare(validationTrigger.sql).run();

    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        api(`/v1/connections/${connection.id}`, { method: "DELETE" }, owner.credential),
      ),
    );
    expect(responses.filter((response) => response.status === 204)).toHaveLength(1);
    expect(responses.every((response) => [204, 404, 409].includes(response.status))).toBe(true);
    expect(await bindings.DB.prepare("SELECT 1 FROM connections").first()).toBeNull();
    expect((await statistics()).revokeCalls).toBe(0);
    expect(
      (await api(`/v1/connections/${connection.id}`, { method: "DELETE" }, owner.credential))
        .status,
    ).toBe(404);
  });

  it("contains cross-tenant locators and stale consent callbacks after disconnect", async () => {
    const owner = await signIn("authority-owner");
    const connected = await connect(owner.credential);
    const pending = await start("/v1/connections/google/start", owner.credential);
    const staleCallback = await authorize(pending);

    const other = await signIn("other-principal");
    expect(
      (
        await post(
          `/v1/connections/google/${pending.transaction_id}/status`,
          { polling_secret: pending.polling_secret },
          other.credential,
        )
      ).status,
    ).toBe(404);
    expect(
      (await api(`/v1/connections/${connected.id}`, { method: "DELETE" }, other.credential)).status,
    ).toBe(404);
    expect(
      (await api(`/v1/devices/${owner.sessionId}`, { method: "DELETE" }, other.credential)).status,
    ).toBe(404);

    expect(
      (await api(`/v1/connections/${connected.id}`, { method: "DELETE" }, owner.credential)).status,
    ).toBe(204);
    await configure({ subject: "authority-owner", email: "same-security@example.test" });
    expect((await exports.default.fetch(new Request(staleCallback))).status).toBe(200);
    expect(await bindings.DB.prepare("SELECT 1 FROM connections").first()).toBeNull();
    expect(await statistics()).toMatchObject({ tokenRequests: 4, revokeCalls: 2 });
  });
});
