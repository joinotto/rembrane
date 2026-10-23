# Rembrane Roadmap

This roadmap describes sequencing, not release dates.

## Phase 0 — Foundation

- [x] Canonical terminology and support boundary.
- [x] Open-source governance and security policy.
- [x] Rust workspace and dependency rules.
- [x] Versioned protocol schemas.
- [x] Threat model and E2EE trust-boundary document.
- [x] Architecture decision records.

## Phase 1 — Secure personal-memory vertical slice

- [x] Model atomic personal workspace and owner initialization.
- [x] Persist local user, workspace, and owner membership in SQLite.
- [ ] Expose local user and personal workspace initialization through the CLI.
- [x] Model confirmed preferences with provenance.
- [x] Model correction and deletion lifecycle operations.
- [x] Define atomic memory, event, and projection mutations.
- [x] Define an opaque record-encryption boundary.
- [x] Define and verify the tenant-isolated SQLite schema.
- [x] Serialize canonical memory records with a versioned format.
- [x] Serialize canonical event records with a versioned format.
- [x] Serialize canonical checkpoint records with a versioned format.
- [ ] Implement the encrypted local SQLite adapter.
- [ ] Retrieve minimal context through REST and MCP.
- [ ] Persist a disclosure receipt for every context response.
- [ ] Prove cross-tenant denial across every adapter read path.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.

## Phase 2 — Development continuity

- [ ] Project entities and scoped preferences.
- [ ] Work-trace event ingestion.
- [x] Model activity checkpoints and resumable handoffs.
- [ ] Git and coding-agent adapters.
- [ ] Context budgets and stale-state detection.

## Phase 3 — Travel continuity

- [ ] Trip entities, participants, constraints, and decisions.
- [ ] Booking-research evidence and expiry.
- [ ] Cross-agent activity continuation.
- [ ] Sensitive travel-data permissions.

## Phase 4 — Shared workspaces

- [ ] Invitations, roles, and entity-level grants.
- [ ] Private-to-shared memory proposals.
- [ ] Group key rotation and member removal.
- [ ] Organizational audit and retention controls.

## Phase 5 — Integration ecosystem

- [ ] Stable Memory Provider Protocol.
- [ ] TypeScript, Python, Rust, Swift, and Kotlin SDKs.
- [ ] Compatibility registry and conformance suite.
- [ ] WhatsApp Business gateway.
- [ ] Mobile share flows and iMessage extension.
- [ ] Community provider and agent adapters.

## Release gates

No stable release until:

- [ ] Tenant-isolation tests pass across every read path.
- [ ] Threat model and recovery model are published.
- [ ] Protocol and encrypted export formats are versioned.
- [ ] Security-sensitive code has independent review.
- [ ] Backup, restore, migration, revocation, and deletion are tested.
