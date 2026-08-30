# TaskNotes Calendar Service

A provider-neutral calendar connection service for TaskNotes clients.

The first implementation target is a Google-only, read-only Cloudflare Worker vertical slice with
federated Google identity, encrypted server-side token custody, per-device sessions, calendar
discovery, and bounded event reads.

The service is under active design and is not ready for real credentials or production use.

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

The HTTP OAuth/session/account slice is implemented. Calendar and event reads deliberately return
`dependency_unavailable` without contacting Google until token refresh and read handlers land in the
next slice.

See:

- [`PRODUCT.md`](PRODUCT.md)
- [`DESIGN.md`](DESIGN.md)
- [`AGENTS.md`](AGENTS.md)
- [`docs/adr/`](docs/adr/)
