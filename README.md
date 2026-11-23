# TaskNotes Calendar Service

A provider-neutral calendar connection service for TaskNotes clients.

A Google-only Cloudflare Worker with federated Google identity, encrypted server-side token custody,
per-device sessions, calendar discovery, bounded and incremental event reads, and a stateless event
write proxy. See [ADR 0005](docs/adr/0005-stateless-write-proxy.md),
[ADR 0007](docs/adr/0007-event-display-fields-and-placement.md) and
[ADR 0008](docs/adr/0008-links-sliding-sessions-and-tolerant-discovery.md).

Reads, writes, incremental changes, and sign-in confirmation passed a supervised live LAB run on
2026-11-06; see [Google readiness](docs/google-readiness.md) for remaining gaps. Staging and
production Workers are deployed. Google approved the production project in November 2026, and the
production TaskNotes build reads `calendar.tasknotes.dev`.

## Local verification

Requires Node 22 and pnpm 11.15.1.

```bash
pnpm install --frozen-lockfile
pnpm migrations:local
pnpm verify
```

Tests run inside the Workers runtime with an isolated D1 database and do not require live Google
credentials. Copy `.dev.vars.example` to the ignored `.dev.vars` and replace every placeholder with
a fake, canonical 32-byte base64url key for local development. `OAUTH_TRANSACTION_KEK_V1` must be
distinct from `TOKEN_KEK_V1`. Local Google endpoints are pinned to the fake provider on
`http://127.0.0.1:9797`; non-local environments accept only pinned production Google endpoints.
`PUBLIC_ORIGIN` is an origin (no path), and the registered redirect is exactly
`/oauth/google/callback`.

The Worker implements OAuth/session/account lifecycle, serialized token refresh, principal-scoped
Calendar discovery, bounded live event pages, incremental changes, stateless event writes, rate
limiting, and hourly cleanup. Calendar mappings are durable opaque identifiers; event bodies and
provider event identifiers are never persisted. Provider pagination and sync tokens are returned
only inside authenticated cursors.

## Client package

`client/` is `@tasknotes/calendar-service-client`, the client the TaskNotes app and the TaskNotes
Obsidian plugin use. See its [README](client/README.md) and
[ADR 0009](docs/adr/0009-published-client-package.md).

```bash
pnpm client:build
pnpm test:unit
pnpm test:e2e
```

`pnpm client:build` writes `client/dist`. The unit tests cover the client against a stand-in
transport, and `test/e2e/client.test.ts` drives it against the Worker.

To publish, set the version in `client/package.json`, merge, and push a tag `client-v<version>`. The
[publish workflow](.github/workflows/publish-client.yml) runs CI and publishes with npm trusted
publishing. Publishing the package does not deploy the Worker.

## Isolated LAB

The non-production Worker reserves `https://tasknotes-calendar-lab.callumalpass.workers.dev`. Its
dedicated D1 database has all migrations applied. The public `workers.dev` trigger is intentionally
disabled between acceptance runs so anonymous OAuth-start traffic cannot write to D1 outside
supervised testing.

The LAB Google client and secret have passed a supervised live sign-in, Calendar consent, discovery,
event-read, event-write, disconnect, and deletion run. The public trigger is disabled between runs.
The Google Web OAuth client registers this exact redirect URI:

```text
https://tasknotes-calendar-lab.callumalpass.workers.dev/oauth/google/callback
```

Future secret rotations must remain interactive rather than entering the value in a file or shell
history:

```bash
pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET --env lab
```

Before another supervised run, explicitly re-enable the LAB `workers_dev` trigger, verify, and
deploy deliberately:

```bash
pnpm migrations:lab:list
pnpm deploy:lab:dry-run
pnpm exec wrangler deploy --env lab
```

These commands target LAB only.

## Staging and production

`wrangler.jsonc` defines `staging` (`https://calendar-staging.tasknotes.dev`) and `production`
(`https://calendar.tasknotes.dev`), each with its own D1 database, secrets, and Google client. The
staging client lives in the `tasknotes-calendar-lab` Google project, and the production client in
`tasknotes-calendar-prod`. Neither environment has a `workers.dev` or preview route.

```bash
pnpm migrations:staging
pnpm exec wrangler deploy --env staging
pnpm migrations:production
pnpm exec wrangler deploy --env production
```

Apply an environment's migrations before deploying a Worker that needs them. Deploy staging first.
Passing it does not by itself approve a production deploy; the release gates in
[ADR 0002](docs/adr/0002-testing-and-release-gates.md) still apply.

Both Workers are pinned to `aws:us-east-1`, beside their D1 databases, because a request makes
several queries. A response's `cf-placement` header shows where it ran. LAB is not pinned.

See:

- [`AGENTS.md`](AGENTS.md)
- [`docs/adr/`](docs/adr/)
