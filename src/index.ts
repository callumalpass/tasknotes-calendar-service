import type { Env } from "./env";
import { createHandlers } from "./http/handlers";
import { withLabCors } from "./http/lab-cors";
import { errorResponse } from "./http/responses";
import { createRouter } from "./http/router";
import { publicOriginFromEnvironment, runtimeConfiguration } from "./runtime/configuration";

const routers = new WeakMap<object, (request: Request) => Promise<Response>>();

function router(env: Env): (request: Request) => Promise<Response> {
  let value = routers.get(env);
  if (value === undefined) {
    value = createRouter(createHandlers(env), {
      authenticate: async (credential) =>
        (await runtimeConfiguration(env)).deviceSessions.authenticate(credential),
    });
    routers.set(env, value);
  }
  return value;
}

export function createWorker(): ExportedHandler<Env> {
  return {
    fetch(request, env): Promise<Response> {
      try {
        if (new URL(request.url).origin !== publicOriginFromEnvironment(env)) {
          return Promise.resolve(errorResponse("resource_not_found"));
        }
        return withLabCors(request, env.ENVIRONMENT, () => router(env)(request));
      } catch {
        return Promise.resolve(errorResponse("internal_error"));
      }
    },
  };
}

export default createWorker();
