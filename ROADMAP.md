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
- [x] Expose local user and personal workspace initialization through the CLI.
- [x] Model confirmed preferences with provenance.
- [x] Authorize confirmed preference creation through an application use case.
- [x] Model correction and deletion lifecycle operations.
- [x] Define atomic memory, event, and projection mutations.
- [x] Define an opaque record-encryption boundary.
- [x] Define and verify the tenant-isolated SQLite schema.
- [x] Add versioned, idempotent SQLite schema initialization.
- [x] Configure bounded SQLite lock waiting and WAL concurrency.
- [x] Serialize canonical memory records with a versioned format.
- [x] Serialize canonical event records with a versioned format.
- [x] Serialize canonical checkpoint records with a versioned format.
- [x] Require an explicit cipher capability for encrypted SQLite memory APIs.
- [x] Implement authenticated, tenant-scoped SQLite memory reads.
- [x] Atomically persist encrypted memories, events, evidence, and projections.
- [x] Persist and optimistically update the SQLite provider projection outbox.
- [x] Persist encrypted activity checkpoints with their audit events.
- [x] Atomically persist exact-version disclosure receipts in SQLite.
- [x] Prototype a portable XChaCha20-Poly1305 record-cipher adapter.
- [x] Implement the encrypted local SQLite adapter.
- [x] Add development-key encrypted CLI remember and recall commands.
- [x] Add encrypted CLI correction and deletion commands.
- [x] Add an executable encrypted CLI lifecycle smoke test.
- [x] Add Postman REST authentication and tenant-isolation smoke tests.
- [x] Add an MCP initialize/list/call protocol smoke test.
- [x] Add a single full preflight test command and operator testing guide.
- [x] Add a secret-safe local installation doctor command.
- [x] Report local processing, connection scopes, endpoints, and secret sources
  through `rembrane doctor --privacy`.
- [x] Add encrypted SQLite backup and verified restore commands.
- [ ] Add production OS-keychain and customer-KMS key providers.
- [x] Retrieve minimal context through local stdio MCP.
- [x] Rank canonical context by deterministic local query relevance.
- [x] Enforce administrator-configured connection read-scope allowlists.
- [x] Bind write permissions to exact administrator-configured scopes.
- [x] Create, correct, and delete authorized preferences through local MCP.
- [x] Create, update, and resume encrypted activity checkpoints through MCP.
- [x] Retrieve minimal context through authenticated local REST.
- [ ] Add remote Streamable HTTP MCP with OAuth.
- [x] Persist a disclosure receipt for every SQLite context response.
- [ ] Persist disclosure receipts in every future storage adapter.
- [x] Prove cross-tenant denial across SQLite user-facing read paths.
- [x] Require workspace identity for internal projection-job lookups.
- [ ] Prove cross-tenant denial across every future adapter read path.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.

## Phase 2 — Development continuity

- [x] Project entities and scoped preferences.
- [x] Layer global, domain, entity, and activity context in one request.
- [x] Activity-scoped work-trace ingestion as proposed observation memory.
- [x] Model activity checkpoints and resumable handoffs.
- [ ] Git and coding-agent adapters.
- [x] Deterministic item and plaintext-byte context budgets.
- [x] Enforce canonical memory and checkpoint payload ceilings.
- [x] Optional external-state fingerprints and stale handoff detection.

## Phase 3 — Travel continuity

- [x] Reuse layered domain/entity context for travel and trip constraints.
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
- [x] Threat model and recovery model are published.
- [ ] Protocol and encrypted export formats are versioned.
- [ ] Security-sensitive code has independent review.
- [ ] Backup, restore, migration, revocation, and deletion are tested.
