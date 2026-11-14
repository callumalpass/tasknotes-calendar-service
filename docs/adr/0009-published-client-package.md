# ADR 0009: One published client for every TaskNotes front end

- Status: Accepted
- Date: 2026-11-14
- Amends: ADR 0002 (what the release gates cover)

## Context

The TaskNotes app carried the only client for this service in its own source. The Obsidian plugin
now signs people in through the service too. A second copy of the client would repeat the sign-in
protocol, the response validation, the retry and conflict rules, and the checks on event links, and
the two copies would drift. A fault in sign-in or validation would then be fixed in one front end
and stay in the other.

The Worker's tests also never ran the client. A Worker change could pass every gate here and still
break the app.

## Decision

This repository publishes the client as `@tasknotes/calendar-service-client`, from `client/`. The
app and the plugin depend on it and keep no client of their own.

### What the package contains

- The sign-in and connection transactions, including the confirmation code.
- Session restore, sign-out, disconnect and account deletion.
- Calendar discovery and the selection of calendars to show.
- Event reads over any range, and event creation, change and deletion with `If-Match`.
- Runtime validation of every response.
- `eventLinks`, which checks an event's links again before a front end offers them.

It contains no interface, no copy shown to a person, and no storage of events.

### What a host supplies

- `origin`: the service to talk to.
- `storage`: a key-value store for the selection and a signed-in flag.
- `host.credentials`: where a bearer session credential is kept, or `null` on the web, where the
  session is an `HttpOnly` cookie.
- `host.openWindow`: how the consent page is opened.
- `transport`: a stand-in for `fetch`, for a host such as Obsidian whose pages cannot call the
  service with `fetch`.

A provider refresh or access token never reaches the package. The only credential it handles is the
service's own bearer session, and it passes that to the host's credential store and nowhere else.

### Compatibility

The package follows semantic versioning, and its version is independent of the Worker's.

The Worker keeps answering every published client version that a TaskNotes front end still ships.
Obsidian users update plugins when they choose to, so an old client stays in use long after a new
one is published. A response may gain fields, because the client ignores fields it does not know. A
change that an already published client cannot read needs a new API version, not a new client
version.

### Tests

The client's unit tests run in this repository against a stand-in transport.
`test/e2e/client.test.ts` drives the client against the Worker in the Workers runtime with D1 and
the fake provider: sign-in with the confirmation code, connection, discovery, event reads and
writes. The release gates of ADR 0002 therefore cover the client, and a Worker change that breaks it
fails here.

`pnpm verify` builds the package, so a change that cannot be published fails CI.

### Publishing

Pushing a tag `client-v<version>` that matches `client/package.json` runs CI and then publishes with
npm trusted publishing, from the `npm` environment. No npm token is stored, and npm attests the
build's provenance. The environment accepts only `client-v*` tags. A pre-release version is
published under the `next` tag.

Publishing the package deploys nothing. The Worker is still deployed as the README describes.

## Consequences

- This repository is public, so that npm can attest where each published version was built. The
  repository holds no secret: keys and client secrets live only in Cloudflare secret storage.
- The first version is published by a person, because npm attaches a trusted publisher only to a
  package that exists. `0.1.0-rc.0` is that version. Every later version comes from the workflow.
- A fix to the client reaches a front end only when that front end takes the new version. The app
  and the plugin each pin an exact version.
- The app keeps its own copy of the client until it moves to the package.
- The package's peer dependency on `zod` accepts versions 3.25 and 4, so each front end keeps the
  one it already bundles.
