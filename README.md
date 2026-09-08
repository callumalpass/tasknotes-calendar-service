# TaskNotes Calendar Service

A provider-neutral calendar connection service for TaskNotes clients.

The first implementation target is a Google-only, read-only Cloudflare Worker vertical slice with
federated Google identity, encrypted server-side token custody, per-device sessions, calendar
discovery, and bounded event reads.

The Google read-only vertical slice is implemented and verified against a signed local provider. It
is not yet approved for real credentials or production use.

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
Calendar discovery, and bounded live event pages. Calendar mappings are durable opaque identifiers;
event bodies and provider event identifiers are never persisted. Provider pagination tokens are
returned only inside authenticated, expiring cursors.

## Isolated LAB

The non-production Worker reserves `https://tasknotes-calendar-lab.callumalpass.workers.dev`. Its
dedicated D1 database is empty and all migrations are applied. The public `workers.dev` trigger is
intentionally disabled between acceptance runs so anonymous OAuth-start traffic cannot write to D1
outside supervised testing.

The LAB Google client and secret have passed a supervised live sign-in, Calendar consent, discovery,
event-read, disconnect, and deletion run. The public trigger is disabled between runs. The Google
Web OAuth client registers this exact redirect URI:

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

These commands target LAB only. Production deployment is not configured.

See:

- [`PRODUCT.md`](PRODUCT.md)
- [`DESIGN.md`](DESIGN.md)
- [`AGENTS.md`](AGENTS.md)
- [`docs/adr/`](docs/adr/)
