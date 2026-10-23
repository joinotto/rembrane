# Changelog

All notable changes to Rembrane will be documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and intends to use semantic versioning after the initial protocol stabilizes.

## [Unreleased]

### Added

- Rust modular-monolith workspace with provider-independent domain and
  application layers.
- Canonical memory, provenance, event, disclosure, membership, grant,
  checkpoint, and projection-outbox models.
- Atomic canonical mutation ports and an in-memory reference adapter.
- Native semantic baseline with authorization revalidation.
- Provider capability verification and retry/quarantine projection worker.
- Versioned discovery, OpenAPI, and MCP protocol specifications.
- Tenant-isolated SQLite canonical schema with encrypted-payload metadata.
- Executable SQLite schema and transaction-atomicity checks.
- Opaque record-encryption boundary with tenant-bound associated data.
- Versioned canonical memory codec with strict decoding and a stable wire
  fixture.
- Versioned canonical event codec covering every lifecycle payload variant.
- Versioned canonical activity-checkpoint codec for resumable handoffs.
- Atomic principal, personal-workspace, and owner-membership bootstrap contract.
- Authorized confirmed-preference creation use case for CLI and protocol
  adapters.
- SQLite adapter for atomic personal-workspace bootstrap and tenant-scoped
  identity and membership lookup.
- `rembrane init` command for an explicitly located local SQLite installation.
- Type-state SQLite cipher attachment that prevents encrypted memory APIs from
  existing on an unconfigured store.
- Tenant-scoped SQLite memory reads that authenticate encrypted payloads before
  canonical decoding.
- Atomic encrypted SQLite memory mutations covering canonical events, evidence,
  and provider projection jobs.
- Persistent SQLite projection outbox with idempotent enqueue, pending work
  reads, and optimistic status transitions.
- Encrypted SQLite activity checkpoints with authenticated resume reads and
  atomic audit events.
- Atomic SQLite disclosure receipts that verify each disclosed memory belongs
  to the subject and is still at the recorded version.
- Experimental RustCrypto XChaCha20-Poly1305 record cipher with randomized
  nonces, zeroizing key storage, and tenant-bound associated data.
- Development CLI flows for encrypted preference capture and minimal-context
  recall with automatic disclosure receipts.
- Encrypted CLI correction and deletion flows with optimistic memory versions.
- Local stdio MCP server using connection-scoped identity to resolve minimal
  encrypted context and record disclosure receipts.
- Bearer-authenticated REST context resolution bound to a configured workspace,
  principal, and client profile.
- End-to-end CLI lifecycle test covering encrypted capture, disclosure,
  correction, deletion, wrong-key rejection, and plaintext-at-rest checks.
- Postman REST suite covering health, bearer authentication, encrypted context
  retrieval, disclosure persistence, and cross-workspace denial.
- MCP stdio protocol smoke test covering initialization, tool discovery,
  context resolution, and disclosure persistence.

### Changed

- Minimum Rust version is 1.88 and the MCP transport targets the official
  `rmcp` 3.4.1 SDK.
- Product architecture, threat model, integration support policy, Rust
  research, bot integration design, and architecture decision records.

### Security

- Workspace identity is mandatory on canonical storage keys.
- CLI, MCP, and REST grants are derived by the shared authorization service
  rather than constructed by transport adapters.
- SQLite tests exercise real authenticated encryption and cross-workspace
  denial for memories, event streams, and activity checkpoints.
- Deleted memories persist an encrypted tombstone envelope rather than an
  ambiguous empty ciphertext.
- Memory and checkpoint writes cannot bypass their corresponding audit event.
- Derived provider projections are atomically enqueued and idempotent.
- Strict E2EE is limited to local or customer-controlled plaintext processing.
- Raw workspace key material is excluded from core storage and provider
  contracts.
