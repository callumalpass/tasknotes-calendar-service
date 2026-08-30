export interface Env {
  DB: D1Database;
  ENVIRONMENT: "local" | "lab" | "staging" | "production";
  PUBLIC_ORIGIN: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_AUTHORIZATION_ENDPOINT: string;
  GOOGLE_TOKEN_ENDPOINT: string;
  GOOGLE_JWKS_URI: string;
  GOOGLE_ISSUER: string;
  GOOGLE_CALENDAR_API_ORIGIN: string;
  TOKEN_KEK_V1: string;
  SESSION_PEPPER: string;
  IDENTITY_FENCE_KEY: string;
  CURSOR_KEY: string;
  EVENT_ID_KEY_V1: string;
}
