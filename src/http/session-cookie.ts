import { ServiceCredentialSchema } from "../contracts";

const SESSION_COOKIE = "__Host-tasknotes_session";
const ATTRIBUTES = "Path=/; Secure; HttpOnly; SameSite=Strict";

export const CLEARED_SESSION_COOKIE = `${SESSION_COOKIE}=; Max-Age=0; ${ATTRIBUTES}`;

export function sessionCookie(credential: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${credential}; Max-Age=${String(maxAgeSeconds)}; ${ATTRIBUTES}`;
}

export function parseSessionCookie(request: Request): string | null {
  const prefix = `${SESSION_COOKIE}=`;
  const values = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => pair.startsWith(prefix));
  if (values.length !== 1) return null;
  const result = ServiceCredentialSchema.safeParse(values[0]?.slice(prefix.length));
  return result.success ? result.data : null;
}
