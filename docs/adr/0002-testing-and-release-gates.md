# ADR 0002: Testing and release gates

- Status: Accepted
- Date: 2026-08-30

## Decision

Correctness evidence must cover the actual Workers runtime and D1 schema, not only mocked
repositories. Tests use deterministic clocks/random sources and a fake Google OAuth/OIDC/Calendar
service with signed JWTs. No CI correctness test depends on live Google credentials.

Before any public beta, P0 suites must prove:

- tenant substitution never authorizes lookup, cache use, or provider work;
- issuer/subject identity uniqueness and same-email separation;
- state, nonce, provider PKCE, TaskNotes PKCE, intent, client, expiry, and callback binding;
- one callback exchange and one session issuance under replay and concurrency;
- device credential hashing, revocation, idle expiry, and renewal on use;
- token-envelope tamper/AAD/key-version failure and rotation safety;
- connection refresh serialization and rotated-refresh-token preservation;
- deletion monotonicity against delayed callbacks, refreshes, and cache fills;
- bounded provider pagination, payload size, date range, retry, and `Retry-After`;
- malicious text and malformed date/time/recurrence payload handling;
- telemetry canaries for every credential and calendar-content category;
- migration from empty D1 and database enforcement of ownership/identity constraints.

The verification command runs formatting, strict typechecking, linting, Worker-runtime tests with
coverage, and Wrangler dry-run packaging. Security-critical crypto, transaction, session, cursor,
and authorization branches target complete branch coverage; global thresholds are secondary.

Remote testing is LAB/staging only until provider verification, privacy and deletion documentation,
key-rotation rehearsal, quota headroom, rollback, and explicit production approval are complete. A
failed LAB test is never redirected to staging or production.

## Evidence discipline

Tests inspect HTTP output, D1 state, provider request count, cache state, and privacy-safe
telemetry. Traces and screenshots are captured only for browser failures. Real credentials, account
identifiers, event payloads, cookies, and tokens never enter agent prompts, repositories, or
retained artifacts.
