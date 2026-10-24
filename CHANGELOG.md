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
- Shared-workspace invitation lifecycle with owner/admin creation authority,
  non-enumerating invitee acceptance, role validation, and atomic membership
  activation in the in-memory reference adapter.
- SQLite schema v3 persistence for tenant-scoped workspace invitations, with
  strict principal foreign keys, one pending invitation per member, and atomic
  invitation acceptance plus membership creation.
- Owner/admin invitation revocation with optimistic pending-state enforcement
  across in-memory and SQLite adapters; revoked invitations cannot later create
  memberships.
- Administrator-managed member scope grants with SQLite schema v4 persistence.
  Member and viewer client scopes are now the exact intersection of requested
  scopes and persisted workspace grants; owners and administrators retain
  unrestricted workspace scope administration.
- Role-hierarchy-enforced member removal with owner protection, optimistic
  membership-state checks, atomic scope-grant cleanup, and immediate denial of
  new client authorization.
- Exact administrator-controlled member scope revocation in both storage
  adapters, with immediate removal from subsequently issued client read and
  write grants while leaving the membership active.
- Atomic canonical mutation ports and an in-memory reference adapter.
- Native semantic baseline with authorization revalidation.
- Provider capability verification and retry/quarantine projection worker.
- Provider protocol `0.1` negotiation with explicit compatibility checks,
  plaintext-processing disclosure, non-zero request limits, and a
  vendor-neutral JSON Schema/example for external adapters.
- Core-enforced provider conformance: projection workers reject incompatible
  or undersized providers before processing, semantic queries are bounded by
  declared limits, and excessive or malformed candidates fail before
  disclosure auditing.
- Reusable semantic-provider conformance harness covering manifest
  compatibility, version fidelity, workspace isolation, declared result
  limits, and deletion propagation, with native-provider and adversarial
  reference tests.
- Evidence-backed provider compatibility registry with a versioned JSON
  Schema, pinned source revisions, explicit deployment/privacy boundaries,
  dated conformance results, and static duplicate/evidence validation.
- Structural validation parity between Rust provider manifests and the public
  JSON Schema, including provider IDs, versions, unique capabilities, and
  non-zero limits.
- `rembrane providers list` for emitting the exact versioned, evidence-backed
  compatibility registry embedded in a CLI build without resolving or printing
  provider credentials.
- `rembrane providers test` for executing the shared destructive-fixture
  conformance suite against an adapter installed in the current CLI build,
  initially supporting the native provider with explicit failure for absent
  adapters.
- Stronger provider conformance coverage for exact v2 replacement,
  superseded-content removal, preservation across deletion through an older
  version, and final deletion propagation.
- OpenAPI 3.1 transport contract and examples for external semantic-provider
  sidecars, including manifest negotiation, idempotent projection upserts,
  workspace-bound search, version-bounded deletion, bounded scores, and
  deployment-resolved bearer authentication.
- Secret-safe black-box HTTP provider conformance runner covering manifest
  negotiation, workspace isolation, exact replacement, version-bounded
  deletion, and cleanup through an isolated disposable namespace.
- Authenticated loopback mock-sidecar test for the HTTP conformance runner,
  including final fixture cleanup and bearer-token output leakage assertions.
- Content-free private-to-shared memory proposal aggregate referencing one
  exact source version and target scope, with source-owner-only approval or
  rejection and proposer/source-owner revocation before disclosure.
- Repository contract and in-memory reference persistence for tenant-scoped
  share proposals, including exact confirmed-source validation, immutable
  identity fields, and optimistic status transitions.
- SQLite schema version 5 and repository persistence for content-free memory
  share proposals, with personal-to-shared workspace constraints, exact
  confirmed-source validation, scoped indexes, and optimistic status updates.
- Canonical approved-share copy construction that preserves the private
  source record, subject attribution, kind, content, and evidence while adding
  a unique approval reference, plus a distinct `ShareMemory` permission.
- Canonical share-proposal, approval, rejection, revocation, and target-copy
  audit events using event wire format v2 while preserving byte-identical v1
  encoding for all pre-existing event variants.
- Dual-workspace memory-share application service and atomic in-memory
  transaction contract, binding source and target grants to one principal and
  client while committing approval, target copy, audit events, and projections
  together.
- SQLite cross-workspace share transaction implementation that revalidates and
  decrypts the exact private source inside the transaction before atomically
  approving the proposal, inserting the shared copy and evidence, appending
  both workspace audit events, and enqueueing target projections.
- SQLite integration coverage for successful persisted sharing and rollback on
  a target-workspace sequence conflict.
- Versioned RustCrypto record-cipher keyring for staged key rotation, using one
  active key for new ciphertext while selecting historical keys strictly by
  envelope key ID for reads and rejecting duplicate key identifiers.
- macOS Keychain workspace-key resolver selected through
  `REMBRANE_KEY_PROVIDER=macos-keychain`, plus provider-aware CLI, privacy
  diagnostics, MCP configuration generation, and secret-safe setup guidance.
- Typed macOS Keychain key references and CLI keyring resolution for one active
  key plus metadata-only historical `key_id=account` entries, allowing old
  ciphertext reads after rotation without exporting key material.
- Key Provider Protocol v0.1 OpenAPI contract and architecture decision for
  authenticated `seal`/`open` operations that keep raw workspace keys inside
  OS-keychain, HSM, or customer-KMS provider boundaries.
- Transport-independent Rust key-provider contracts for protocol negotiation,
  algorithm and historical-key capabilities, complete encryption contexts,
  bounded plaintext requests, and bounded open responses.
- Expanded dependency-free core verification to compile, test, and lint the
  cryptographic boundary and key-provider contracts.
- Secret-safe key-provider HTTP conformance runner covering bearer
  authentication, manifest limits, envelope shape, round trips, cross-workspace
  context substitution, unknown keys, oversized plaintext, and token leakage.
- Transport-neutral key-provider `RecordCipher` client that negotiates one
  manifest, generates bounded monotonic request IDs, rejects oversized
  plaintext before transport, enforces the selected algorithm, and rejects
  oversized open responses.
- Canonical versioned trip aggregate with real-calendar date validation,
  destinations, opaque participant identities, participant-scoped
  evidence-backed constraints, attributed proposed/selected/rejected
  decisions, duplicate denial, and aggregate payload ceilings.
- Strict trip restoration path for persistence adapters, rejecting zero
  versions, duplicate nested identities, dangling participant references, and
  reconstructed aggregates over the canonical size ceiling.
- Versioned `rembrane.trip` wire format covering the complete trip aggregate,
  with unknown-field denial and decoding exclusively through the strict domain
  restoration path.
- Versioned discovery, OpenAPI, and MCP protocol specifications.
- Tenant-isolated SQLite canonical schema with encrypted-payload metadata.
- Versioned SQLite initialization with legacy-schema adoption, idempotent
  reopen behavior, and rejection of unsupported future schema versions.
- SQLite connections configured with foreign-key enforcement, a bounded
  five-second lock wait, and WAL journaling for concurrent local agents.
- Executable SQLite schema and transaction-atomicity checks.
- Opaque record-encryption boundary with tenant-bound associated data.
- Typed native, Mem0, and Graphiti provider connection profiles with
  secret-reference-only credentials, HTTPS-or-loopback enforcement, and
  credential-bearing URL rejection.
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
- Idempotent `rembrane init` reruns for the same healthy personal workspace,
  while conflicting or partial existing state still fails closed.
- `rembrane doctor` preflight for database compatibility, workspace
  membership, key authentication, and readable encrypted-memory counts without
  printing secret values.
- `rembrane doctor --privacy` diagnostics for local processing placement,
  exact configured read scopes, outbound endpoints, and secret-source names.
- Privacy diagnostics redact user information, paths, queries, and fragments
  from configured Mem0, Graphiti, object-storage, and remote MCP endpoints.
- `doctor --privacy` validates configured Mem0 and Graphiti profiles and fails
  closed on insecure or credential-bearing endpoints before adapter use.
- CLI end-to-end assertions for privacy diagnostics and their exact
  administrator-owned scope allowlist.
- Consistent encrypted SQLite backups and fail-closed restores that refuse
  overwrites, authenticate restored records, and remove invalid destinations.
- Backup, restore, and doctor verification now authenticate every encrypted
  memory, event, and activity checkpoint, with explicit ciphertext-tamper
  denial coverage.
- `rembrane-encrypted-export-v1` single-file backup framing with strict magic,
  format-version, payload-length, truncation, and trailing-data validation.
- Read-only `rembrane fingerprint-git` command producing stable
  `git:<commit>:<clean|dirty>` handoff fingerprints without repository locks.
- Secret-safe `rembrane mcp-config` generators for Codex TOML and Claude Code
  JSON, forwarding credential names from the local environment without
  printing credential values.
- Versioned vendor-neutral stdio connection manifest and JSON Schema for
  credential-free integration with other MCP-capable apps, bots, and agents.
- Type-state SQLite cipher attachment that prevents encrypted memory APIs from
  existing on an unconfigured store.
- Tenant-scoped SQLite memory reads that authenticate encrypted payloads before
  canonical decoding.
- Atomic encrypted SQLite memory mutations covering canonical events, evidence,
  and provider projection jobs.
- Persistent SQLite projection outbox with idempotent enqueue, pending work
  reads, and optimistic status transitions.
- Workspace-qualified projection-job lookup contracts and cross-workspace
  denial tests; globally unique job IDs are no longer treated as authority.
- Persistent SQLite membership-revocation coverage proving removed principals
  cannot receive fresh read or write client grants.
- Subject-isolation tests for encrypted SQLite memory-list and activity
  checkpoint reads within the same workspace.
- Encrypted SQLite activity checkpoints with authenticated resume reads and
  atomic audit events.
- Versioned SQLite checkpoint-disclosure receipts recording the exact
  checkpoint revision, activity, subject, client, and purpose returned during
  MCP cross-agent resume.
- Explicit denial coverage proving unauthorized checkpoint resume creates no
  disclosure receipt.
- Atomic SQLite disclosure receipts that verify each disclosed memory belongs
  to the subject and is still at the recorded version.
- Experimental RustCrypto XChaCha20-Poly1305 record cipher with randomized
  nonces, zeroizing key storage, and tenant-bound associated data.
- Development CLI flows for encrypted preference capture and minimal-context
  recall with automatic disclosure receipts.
- Deterministic local relevance ranking that suppresses unrelated canonical
  memories when a query has matching context.
- Layer-aware relevance filtering now keeps the strongest selected match per
  scope after byte budgeting, preserving smaller fallback memories and layered
  global/entity/activity context.
- Deterministic plaintext-byte context budgets across canonical, semantic,
  CLI, REST, and MCP resolution paths.
- Domain-enforced 256 KiB ceilings for canonical memory content and complete
  activity-checkpoint payloads across every transport and adapter.
- Encrypted CLI correction and deletion flows with optimistic memory versions.
- Local stdio MCP server using connection-scoped identity to resolve minimal
  encrypted context and record disclosure receipts.
- MCP tools for authorized direct preference creation, correction, and
  encrypted deletion tombstones.
- MCP tools for encrypted activity checkpoint creation, optimistic updates,
  and scoped cross-agent resume.
- Backward-compatible encrypted checkpoint state fingerprints with MCP stale
  handoff detection for changed Git, filesystem, booking, or other state.
- MCP work-trace ingestion as encrypted, activity-scoped proposed observation
  memory, preserving the boundary between agent evidence and confirmed truth.
- Bearer-authenticated REST context resolution bound to a configured workspace,
  principal, and client profile.
- Exact `REMBRANE_READ_SCOPES` connection allowlists for global, domain,
  entity, and activity context across REST and MCP; request payloads cannot
  expand the administrator-owned grant.
- REST and MCP startup denial tests for wildcard read-scope configuration.
- Scope-bound write grants enforced by memory creation, proposal, confirmation,
  revision, deletion, and activity-checkpoint use cases.
- CLI and MCP preference capture across global, domain, entity/project, and
  activity scopes with mutually exclusive scope selectors.
- Layered CLI recall combining common global memory with requested domain,
  entity/project, and activity context.
- Encrypted travel-domain and trip-entity continuity coverage in the CLI
  end-to-end lifecycle.
- Scope-aware CLI and MCP correction/deletion flows that require callers to
  retain authority over the memory's exact scope.
- End-to-end CLI lifecycle test covering encrypted capture, disclosure,
  correction, deletion, wrong-key rejection, and plaintext-at-rest checks.
- Postman REST suite covering health, bearer authentication, encrypted context
  retrieval, disclosure persistence, and cross-workspace denial.
- REST end-to-end coverage for an allowed project entity and denial of a
  neighboring entity outside the same connection grant.
- MCP stdio protocol smoke test covering initialization, tool discovery,
  context resolution, and disclosure persistence.
- One-command full preflight suite, environment template, and manual testing
  guide for CLI, MCP, and REST.
- Protocol preflight covering OpenAPI YAML, discovery JSON, Postman, MCP smoke
  syntax, implemented-tool documentation, and REST route consistency.
- Standalone non-Rust static suite for restricted or offline development
  environments, reused by the complete compiler and end-to-end suite.
- Executable local-alpha acceptance contract and independent CI jobs for
  static/schema checks, the complete Rust/E2E suite, and container builds.
- Offline `--core` acceptance mode compiling, testing, and Clippy-checking all
  dependency-free packages without resolving the external Cargo registry.
- Roadmap release gates reconciled with executable local-alpha lifecycle and
  tenant-isolation coverage while future-adapter and independent-review gates
  remain open.
- Multi-stage Docker image and loopback-only Compose profile with idempotent
  workspace bootstrap, non-root application execution, encrypted persistent
  storage, and an authenticated-data health check.

### Changed

- Workspace lint policy documents constructor-arity and public error-doc
  exceptions while retaining warnings-as-errors for actionable Clippy checks.
- Minimum Rust version is 1.88 and the MCP transport targets the official
  `rmcp` 3.4.1 SDK.
- MCP application errors now separate safe validation/conflict feedback from
  non-enumerating authorization failures and generic backend failures.
- MCP and REST end-to-end fixtures now prove that connection scope allowlists
  permit configured activities while denying model-requested scope expansion.
- Product architecture, threat model, integration support policy, Rust
  research, bot integration design, and architecture decision records.
- Explicit strict-E2EE recovery model covering encrypted backups, key loss,
  rollback risk, restore verification, and shared-workspace limitations.

### Security

- Workspace identity is mandatory on canonical storage keys.
- CLI, MCP, and REST grants are derived by the shared authorization service
  rather than constructed by transport adapters.
- Development workspace key decoding is centralized in the crypto adapter and
  zeroized before returning a cipher.
- SQLite tests exercise real authenticated encryption and cross-workspace
  denial for memories, event streams, and activity checkpoints.
- Deleted memories persist an encrypted tombstone envelope rather than an
  ambiguous empty ciphertext.
- Memory and checkpoint writes cannot bypass their corresponding audit event.
- Derived provider projections are atomically enqueued and idempotent.
- Strict E2EE is limited to local or customer-controlled plaintext processing.
- Raw workspace key material is excluded from core storage and provider
  contracts.
