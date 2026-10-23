# ADR 0005: Canonical mutations and events are atomic

- Status: Accepted
- Date: 2026-10-23

## Context

Rembrane maintains current canonical projections for efficient reads and an append-only event stream for evidence, synchronization, reconstruction, and audit. Writing a projection without its event—or an event without its projection—would create inconsistent history.

Semantic, graph, vector, and artifact providers cannot participate reliably in the canonical database transaction.

## Decision

A canonical mutation transaction must atomically:

1. Validate identity, workspace, subject, grant, and expected version.
2. Append the canonical event with the next workspace sequence.
3. Update the canonical record or deletion tombstone.
4. Insert durable outbox records for derived providers.

The transaction commits before derived projection work begins.

Workers consume the outbox idempotently and update:

- Semantic-memory engines.
- Vector indexes.
- Knowledge graphs.
- Search indexes.
- Optional integration notifications.

Each projection records canonical ID, version, provider, and processing status. A newer canonical version supersedes older queued projection work.

Context resolution re-authorizes provider candidates against canonical records and exact versions. A provider result is never evidence that access is allowed.

## Failure behavior

- Canonical transaction failure exposes no partial mutation.
- Provider outage leaves retryable outbox work and does not roll back canonical truth.
- Deletion creates a canonical tombstone immediately; context resolution excludes it even while provider deletion is pending.
- Provider deletion failures remain visible in administrative and privacy diagnostics.
- Poison messages enter a quarantined state after bounded retries; they are not silently discarded.

## Consequences

- PostgreSQL is the initial hosted authority because it can transact records, events, versions, and outbox entries together.
- SQLite provides the equivalent local transaction.
- Provider adapters must implement idempotent projection keys.
- “Exactly once” is not assumed across external providers; Rembrane uses at-least-once delivery with version-aware idempotency.
- The current volatile reference adapter is for tests and prototypes until its mutation helpers model this atomic boundary.
