# TaskNotes Calendar Service

A provider-neutral calendar connection service for TaskNotes clients.

The first implementation target is a Google-only, read-only Cloudflare Worker vertical slice with
federated Google identity, encrypted server-side token custody, per-device sessions, calendar
discovery, and bounded event reads.

The service is under active design and is not ready for real credentials or production use.

See:

- [`PRODUCT.md`](PRODUCT.md)
- [`DESIGN.md`](DESIGN.md)
- [`AGENTS.md`](AGENTS.md)
- [`docs/adr/`](docs/adr/)
