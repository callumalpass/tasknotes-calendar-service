type Bindings = {
  [Binding in keyof Cloudflare.Env]: Cloudflare.Env[Binding] extends string
    ? string
    : Cloudflare.Env[Binding];
};

export interface Env extends Omit<Bindings, "ENVIRONMENT"> {
  ENVIRONMENT: "local" | "lab" | "staging" | "production";
  GOOGLE_CLIENT_SECRET: string;
  OAUTH_TRANSACTION_KEK_V1: string;
  TOKEN_KEK_V1: string;
  SESSION_PEPPER: string;
  IDENTITY_FENCE_KEY: string;
  CURSOR_KEY: string;
  EVENT_ID_KEY_V1: string;
}
