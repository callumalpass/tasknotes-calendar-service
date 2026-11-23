# Repository guidance

## Avoid additive complexity

Rapid AI-assisted development can amplify ordinary engineering failure modes: locally safe additions
accumulate faster than old mechanisms are removed; uncertainty becomes optional state, defensive
branches, fallbacks, and compatibility; conformance work produces parallel adapters instead of one
canonical implementation; and inexpensive code generation weakens the natural pressure to simplify.

Target these mechanisms regardless of who wrote the code. Do not assume that defensive code,
compatibility, abstraction, or product breadth is inherently wrong; evaluate each against concrete
invariants, consumers, persisted representations, tests, and ownership boundaries.

Before handing off a change, ask:

- What existing mechanism does this replace and delete?
- What evidence proves each new state or fallback is reachable?
- Is expected invalid input distinguished from an internal invariant failure?
- Does compatibility name its consumer and removal condition?
- Does each new abstraction represent a real boundary or repeated concept?
- Does the change expand public, persisted, configured, or user-facing state?
- Has the change produced net simplification?

Prefer strong invariants over defensive hedging, replacement over accumulation, explicit failure
over silent recovery, and simplification over expansion.

## Product and trust boundary

- This service belongs to TaskNotes and is independent of mdbase identity, subscriptions,
  entitlements, collections, and record payloads.
- Provider refresh tokens terminate here. They must never be returned to a TaskNotes client, written
  to logs, placed in URLs, or stored in an mdbase collection.
- Email is display metadata, never identity. External identities are keyed by a validated provider,
  canonical issuer, and immutable subject.
- Every lookup, cache read, provider request, queue job, and mutation must derive authority from the
  authenticated principal. Opaque IDs convey no authority.
- Account deletion and connection revocation dominate delayed callbacks, cache fills, queue retries,
  token refreshes, and scheduled work through explicit generations or tombstones.

## Development discipline

- Read the relevant ADR before changing a public, persisted, configured, security-sensitive, or
  user-facing contract.
- Stay Google-only and within the stateless write proxy of ADR 0005. Do not add Microsoft,
  persistent event mirroring, server-side sync, or mdbase materialization until their ADR gate is
  accepted.
- Use strict TypeScript, runtime validation at every external boundary, native Web APIs, explicit
  SQL migrations, and versioned queue/API contracts.
- Prefer direct provider REST adapters over broad SDK abstractions. Treat all provider payloads,
  pagination tokens, URLs, dates, and text as untrusted.
- Never add plaintext token compatibility, best-effort authorization, automatic identity merging,
  public user-data caching, or silent recovery from invariant failures.
- Tests must cover the real Worker runtime and D1 semantics in addition to pure units.
  Security-critical state transitions require concurrency, replay, deletion, tenant-substitution,
  fault-injection, and telemetry-canary tests.
- LAB and staging only until all documented release gates pass. Never redirect a failed
  non-production test to production.
- Secrets live only in Cloudflare secret storage or local ignored test files. Never commit, print,
  prompt an agent with, or persist real credentials in test artifacts.

## Required verification

Before handoff, run the repository's format check, typecheck, lint, unit tests, Worker-runtime
integration tests, migration tests, adversarial security suite, and local end-to-end tests. Run
remote LAB smoke/e2e tests when deployment or runtime bindings change. Report unavailable or blocked
coverage explicitly; never claim it passed without evidence.
