import type { Env } from "./env";
import { createHandlers } from "./http/handlers";
import { createRouter } from "./http/router";
import {
  allowedOriginsFromEnvironment,
  publicOriginFromEnvironment,
  runtimeConfiguration,
} from "./runtime/configuration";

const routers = new WeakMap<object, ReturnType<typeof createRouter>>();

function router(env: Env): ReturnType<typeof createRouter> {
  let value = routers.get(env);
  if (value === undefined) {
    value = createRouter(
      createHandlers(env),
      {
        authenticate: async (credential) =>
          (await runtimeConfiguration(env)).deviceSessions.authenticate(credential),
      },
      {
        rateLimiters: { ip: env.IP_RATE_LIMITER, principal: env.PRINCIPAL_RATE_LIMITER },
        allowedOrigins: () => allowedOriginsFromEnvironment(env),
        publicOrigin: () => publicOriginFromEnvironment(env),
      },
    );
    routers.set(env, value);
  }
  return value;
}

export function createWorker() {
  return {
    fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
      return router(env)(request, ctx);
    },
    async scheduled(_controller, env): Promise<void> {
      // Fences only reject transactions created before deletion; their 10-minute lifetime is below one hour.
      await env.DB.batch([
        env.DB.prepare(`DELETE FROM oauth_transactions WHERE id IN (
          SELECT id FROM oauth_transactions WHERE expires_at <= unixepoch() ORDER BY expires_at LIMIT 100
        )`),
        env.DB.prepare(`DELETE FROM device_sessions WHERE id IN (
          SELECT id FROM device_sessions WHERE revoked_at IS NOT NULL
            OR idle_expires_at <= unixepoch() OR absolute_expires_at <= unixepoch()
          ORDER BY idle_expires_at LIMIT 100
        )`),
        env.DB.prepare(`DELETE FROM identity_deletion_fences WHERE identity_digest IN (
          SELECT identity_digest FROM identity_deletion_fences WHERE deleted_at < unixepoch() - 3600
          ORDER BY deleted_at LIMIT 100
        )`),
      ]);
    },
  } satisfies ExportedHandler<Env>;
}

export default createWorker();
