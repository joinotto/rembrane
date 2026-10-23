# Rembrane Roadmap

This roadmap describes sequencing, not release dates.

## Phase 0 — Foundation

- Canonical terminology and support boundary.
- Open-source governance and security policy.
- Rust workspace and dependency rules.
- Versioned protocol schemas.
- Threat model and E2EE trust-boundary document.
- Architecture decision records.

## Phase 1 — Secure personal-memory vertical slice

- Create a local user and personal workspace.
- Store a confirmed preference with provenance.
- Retrieve minimal context through REST and MCP.
- Record a disclosure receipt.
- Correct, supersede, and delete a memory.
- Prove cross-tenant denial with automated tests.
- Provide local SQLite and hosted PostgreSQL adapters.

## Phase 2 — Development continuity

- Project entities and scoped preferences.
- Work-trace event ingestion.
- Activity checkpoints and resumable handoffs.
- Git and coding-agent adapters.
- Context budgets and stale-state detection.

## Phase 3 — Travel continuity

- Trip entities, participants, constraints, and decisions.
- Booking-research evidence and expiry.
- Cross-agent activity continuation.
- Sensitive travel-data permissions.

## Phase 4 — Shared workspaces

- Invitations, roles, and entity-level grants.
- Private-to-shared memory proposals.
- Group key rotation and member removal.
- Organizational audit and retention controls.

## Phase 5 — Integration ecosystem

- Stable Memory Provider Protocol.
- TypeScript, Python, Rust, Swift, and Kotlin SDKs.
- Compatibility registry and conformance suite.
- WhatsApp Business gateway.
- Mobile share flows and iMessage extension.
- Community provider and agent adapters.

## Release gates

No stable release until:

- Tenant-isolation tests pass across every read path.
- Threat model and recovery model are published.
- Protocol and encrypted export formats are versioned.
- Security-sensitive code has independent review.
- Backup, restore, migration, revocation, and deletion are tested.
