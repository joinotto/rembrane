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
- [x] Audit every externally resumed checkpoint revision with a tenant-scoped
  disclosure receipt.
- [x] Atomically persist exact-version disclosure receipts in SQLite.
- [x] Prototype a portable XChaCha20-Poly1305 record-cipher adapter.
- [x] Define validated native, Mem0, and Graphiti connection profiles using
  secret references rather than stored credential values.
- [x] Implement the encrypted local SQLite adapter.
- [x] Add development-key encrypted CLI remember and recall commands.
- [x] Add encrypted CLI correction and deletion commands.
- [x] Add an executable encrypted CLI lifecycle smoke test.
- [x] Add Postman REST authentication and tenant-isolation smoke tests.
- [x] Add an MCP initialize/list/call protocol smoke test.
- [x] Add a single full preflight test command and operator testing guide.
- [x] Publish an executable local-alpha acceptance contract with independent
  static, Rust/E2E, and container CI gates.
- [x] Add a secret-safe local installation doctor command.
- [x] Report local processing, connection scopes, endpoints, and secret sources
  through `rembrane doctor --privacy`.
- [x] Add encrypted SQLite backup and verified restore commands.
- [x] Package the local REST service for loopback-only Docker Compose
  self-hosting with persistent encrypted storage.
- [ ] Add production OS-keychain and customer-KMS key providers.
  - [x] Honor environment or macOS Keychain selection uniformly in the CLI,
    REST API, and MCP server, including historical-key reads.
  - [x] Support active-key writes and historical-key reads through a
    duplicate-safe versioned record-cipher keyring.
  - [x] Resolve a single active key from macOS Keychain without environment
    key material.
  - [x] Resolve active and historical rotating keyrings from macOS Keychain
    using metadata-only references.
  - [ ] Add Windows DPAPI and Linux Secret Service adapters.
  - [x] Define a vendor-neutral authenticated key-provider operation protocol
    that never exports raw workspace keys.
  - [ ] Resolve or unwrap keyring material through customer KMS adapters.
  - [x] Add a provider-agnostic configured cipher that dispatches to local
    environment/macOS keyrings or a policy-negotiated HTTP key provider.
  - [x] Wire configured cipher selection through CLI, REST, MCP, generated
    agent configuration, and privacy diagnostics.
- [x] Retrieve minimal context through local stdio MCP.
- [x] Rank canonical context by deterministic local query relevance.
- [x] Enforce administrator-configured connection read-scope allowlists.
- [x] Bind write permissions to exact administrator-configured scopes.
- [x] Create, correct, and delete authorized preferences through local MCP.
- [x] Create, update, and resume encrypted activity checkpoints through MCP.
- [x] Retrieve minimal context through authenticated local REST.
- [ ] Add remote Streamable HTTP MCP with OAuth.
  - [x] Define HTTPS endpoints, RFC 9728 discovery metadata, bearer challenges,
    verified connection identity, scope ceilings, and session security rules.
  - [x] Serve opt-in RFC 9728 protected-resource metadata from the HTTP
    service, requiring an exact HTTPS resource and authorization-server pair.
  - [x] Add a fail-closed verified-token claims contract.
  - [x] Add a transport-independent authentication boundary backed by a
    signature-verifying or authenticated-introspection adapter.
  - [x] Add an RFC 7662 authenticated-introspection adapter with a
    replaceable bounded HTTP transport.
    - [x] Provide a concrete HTTPS transport with authenticated client
      credentials, strict timeouts, no redirects, and bounded responses.
  - [x] Map every current MCP tool to one narrow OAuth scope and fail closed
    for unknown tools.
  - [x] Add transport-neutral HTTP authorization middleware with strict bearer
    parsing, trusted-origin checks, fail-closed tool lookup, and per-request
    reauthentication.
    - [x] Authenticate initialize, discovery, event-stream, and session-delete
      requests without granting a tool scope they did not request.
  - [ ] Integrate the authorization middleware with the HTTP server adapter.
    - [x] Validate complete remote profiles before startup, including exact
      HTTPS endpoints, referenced client secrets, and exact browser origins.
      - [x] Reject non-ASCII, whitespace, controls, quotes, and malformed
        authorities before configuration values can reach HTTP headers.
      - [x] Derive one canonical RFC 9728 metadata URL and bearer challenge
        from an encapsulated profile that cannot be mutated after validation.
    - [x] Provide one transport-neutral lifecycle boundary that composes
      per-request HTTP authorization with session establish, revalidation,
      tool-scope enforcement, and authenticated deletion.
    - [x] Classify the exact supported MCP JSON-RPC method surface and reject
      unknown methods, missing tool names, and method/tool mismatches before
      dispatch.
    - [x] Preserve transport-facing bearer outcomes so adapters return 401 for
      invalid credentials and 403 only for authenticated but forbidden
      origins, tools, or scopes.
  - [x] Allow the shared MCP handler service to initialize canonical
    subject/client/workspace identity exclusively from verified remote claims.
  - [x] Bind remote sessions to issuer, resource, canonical identity,
    workspace, exact OAuth scope ceiling, and a non-extending expiry.
  - [x] Add a bounded session registry with URL-safe identifiers,
    duplicate/capacity controls, per-request revalidation, and authenticated
    deletion, reclaiming expired capacity before accepting new sessions.
  - [ ] Serve Streamable HTTP through the official Rust MCP SDK.
  - [ ] Add OAuth and cross-tenant transport integration tests.
    - [x] Prove verified remote identity is still constrained by canonical
      workspace membership, audience, expiry, and token validity.
  - [x] Add a hardened Cloudflare Tunnel Compose overlay that keeps persistent
    memory and encryption credentials on the operator-controlled origin.
- [x] Persist a disclosure receipt for every SQLite context response.
- [ ] Persist disclosure receipts in every future storage adapter.
- [x] Prove cross-tenant denial across SQLite user-facing read paths.
- [x] Require workspace identity for internal projection-job lookups.
- [ ] Prove cross-tenant denial across every future adapter read path.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.

## Phase 2 — Development continuity

- [ ] Canonical temporal knowledge graph.
  - [x] Define engine-neutral, typed workspace-scoped nodes and relationships
    with separate event/system time, validity windows, provenance, bounded
    aliases, and explicit supersession references.
  - [x] Add tenant-isolated mutation and neighbourhood repository contracts
    with bounded temporal traversal and optimistic version checks.
  - [ ] Add local SQLite graph persistence and Graphiti projection adapter.
    - [x] Persist tenant-isolated temporal graph aggregates as authenticated
      ciphertext with bounded indexed neighbourhood traversal.
    - [x] Define an engine-neutral graph provider contract and conformance
      harness for workspace isolation, validity windows, and deletion.
    - [x] Add a deterministic dependency-free native graph provider as the
      conformance and benchmark baseline.
    - [x] Model durable graph projection work independently from semantic
      memory projection jobs.
    - [x] Persist graph projection jobs in SQLite with idempotent provider
      polling and optimistic transitions.
    - [ ] Add Graphiti projection adapter.

- [x] Project entities and scoped preferences.
- [x] Layer global, domain, entity, and activity context in one request.
- [x] Activity-scoped work-trace ingestion as proposed observation memory.
- [x] Model activity checkpoints and resumable handoffs.
- [x] Deterministic local Git state fingerprints for coding-agent handoffs.
- [x] Secret-safe Codex and Claude Code stdio MCP configuration generators.
- [x] Versioned vendor-neutral stdio connection manifest for apps, bots, and
  agent launchers.
- [ ] Additional native coding-agent configuration adapters.
  - [x] Generate a secret-safe Gemini CLI `settings.json` MCP fragment.
- [x] Deterministic item and plaintext-byte context budgets.
- [x] Enforce canonical memory and checkpoint payload ceilings.
- [x] Optional external-state fingerprints and stale handoff detection.

## Phase 3 — Travel continuity

- [x] Reuse layered domain/entity context for travel and trip constraints.
- [x] Trip entities, participants, constraints, and decisions.
  - [x] Canonical versioned trip aggregate with opaque participants, validated
    date windows, evidence-backed constraints, and attributed decisions.
  - [x] Versioned canonical trip wire format with strict aggregate
    reconstruction.
  - [x] Authorized create/revise application service with exact entity-scoped
    grants and an atomic in-memory reference repository.
  - [x] Dedicated travel-domain capability for creating new trip entities;
    revisions remain exact-entity scoped.
  - [x] Encrypted persistent trip repository with tenant-isolation and rollback
    coverage.
    - [x] Versioned SQLite schema and encrypted atomic trip/event repository.
    - [x] Executable encrypted tenant-isolation, optimistic revision, and
      rollback adapter tests.
- [x] Booking-research evidence and expiry.
  - [x] Canonical evidence-backed booking-research record with strict UTC
    observation and expiry semantics.
  - [x] Versioned provider-independent booking-research codec.
  - [x] Exact trip-scoped capture authorization and atomic in-memory reference
    repository.
  - [x] Workspace-bound encrypted SQLite repository with atomic audit events.
  - [x] Authenticated REST capture contract and server route.
  - [x] MCP capture tool using connection-bound identity and exact trip scope.
  - [x] REST/Postman and MCP protocol tests reject capture without a canonical
    trip.
  - [x] Successful MCP trip creation and booking-research capture lifecycle.
  - [x] Authenticated REST trip-creation contract and server route.
  - [x] Successful REST/Postman encrypted trip-to-research lifecycle test.
  - [x] Narrow optimistic participant mutation over REST and MCP preserves
    unrelated trip state and uses server-assigned participant identity.
  - [x] Narrow evidence-backed constraint and attributed-decision mutations
    over REST and MCP, with server-assigned record identity.
- [x] Cross-agent activity continuation.
  - [x] Exact-trip travel context separates fresh research from expired
    observations at a caller-supplied canonical timestamp.
  - [x] Audited REST/MCP travel context retrieval and exact-version disclosure
    receipts, with opaque provider source references excluded from responses.
- [x] Sensitive travel-data permissions.
  - [x] MCP trip creation uses a dedicated travel-domain capability and
    server-assigned identity.
  - [x] Source references are redacted by default and require both explicit
    request intent and an owner/admin connection permission.
  - [x] Application-level safe projections prevent transport adapters from
    bypassing source-reference redaction.
  - [x] Disclosure receipts distinguish redacted responses from privileged
    source-reference disclosures.
  - [x] Participant labels and sensitive constraint details require a distinct
    `travel-sensitive-profile` connection permission and per-request intent.
    - [x] Define and owner/admin-gate the distinct read permission.
    - [x] Return an application-level safe trip projection that omits the
      sensitive profile unless both permission and request intent are present.
    - [x] Record sensitive-profile inclusion in version 10 disclosure receipts.

## Phase 4 — Shared workspaces

- [x] Shared-workspace invitations and role-bound acceptance.
- [x] Shared-workspace exact scope grants, including entity-level access.
- [ ] Private-to-shared memory proposals.
  - [x] Content-free, exact-source-version proposal aggregate with source-owner
    approval, rejection, and pre-approval revocation.
  - [x] Tenant-scoped SQLite persistence with exact-source and workspace-kind
    constraints.
  - [x] Versioned canonical audit events and approved target-copy construction.
  - [x] Dual-workspace authorization and atomic in-memory reference transaction.
  - [x] SQLite atomic approval and target-workspace copy implementation.
  - [ ] Verify the dependency-enabled SQLite integration suite in CI.
- [x] Authorized member removal with atomic scope-grant cleanup.
- [ ] Group key rotation after membership changes.
- [ ] Organizational audit and retention controls.

## Phase 5 — Integration ecosystem

- [x] Versioned pre-alpha provider manifest with capability, privacy, and
  request-limit negotiation.
- [x] Enforce provider protocol and declared limits at projection and retrieval
  boundaries.
- [x] Versioned HTTP sidecar contract for external semantic providers.
- [x] Secret-safe black-box HTTP sidecar conformance runner.
- [ ] Stable Memory Provider Protocol.
  - [x] Add an immutable, versioned discovery manifest with standard well-known
    path, transports, operation capabilities, privacy mode, supported domains,
    and bounded context/event/sync limits.
  - [x] Register each portable operation with exactly one capability, narrow
    OAuth scope, HTTP method, and stable path template.
  - [x] Add fail-closed provider negotiation over protocol version, transport,
    required capabilities, allowed privacy modes, and minimum operation limits.
  - [x] Bind typed request creation to the negotiated manifest with unique
    correlation IDs and per-operation advertised-capability enforcement.
  - [x] Reject transport responses correlated to another request or protocol
    version before exposing their typed result bodies.
  - [x] Define transport-neutral request and response envelopes with bounded
    correlation IDs, protocol negotiation, operation binding, and closed
    portable error codes.
    - [x] Seal Rust payload-to-operation mappings so callers cannot pair a
      valid payload with a different privileged operation.
    - [x] Associate every Rust request payload with its canonical result type
      so unrelated success bodies cannot be attached to an operation.
  - [x] Define canonical operation payloads and validation.
    - [x] Add bounded context-resolution requests with global, domain, entity,
      and activity selectors constrained by provider-advertised limits.
      - [x] Seal selector representation so callers cannot bypass domain and
        opaque-ID validation through direct enum construction.
    - [x] Add bounded context responses carrying canonical IDs, versions,
      scopes, kinds, evidence, confidence, validity, sensitivity, disclosure
      constraints, and disclosure receipts.
    - [x] Add idempotent memory-proposal payloads that preserve validated
      scope, memory kind, provenance source, and observation time without
      allowing clients to assert confirmed status.
    - [x] Add bounded idempotent activity-checkpoint create/update payloads
      with explicit optimistic versions and canonical checkpoint identities.
    - [x] Add append-only disclosure receipt payloads containing exact memory
      revisions while deriving workspace, subject, and client identity solely
      from authenticated connection context.
    - [x] Add exact-version idempotent deletion and bounded provenance
      explanation payloads without caller-controlled authorization identity.
    - [x] Add idempotent bounded event-batch payloads with exact scope,
      provenance references, observation time, and canonical ordered results.
    - [x] Add bounded scoped question payloads and answers grounded in exact
      memory revisions with context-pack and disclosure receipt identity.
    - [x] Add cursor-bound bounded sync pull/push payloads with server-assigned
      ordering, optimistic atomic mutations, ciphertext-compatible content
      digests, and no caller-controlled tenant identity.
  - [x] Publish a serialization schema and HTTP binding.
    - [x] Publish strict canonical JSON primitives, discovery manifest, closed
      enums, selectors, and transport-neutral envelope schemas.
    - [x] Bind every operation payload and result to its canonical JSON schema.
      - [x] Bind context resolution, grounded questions, exact-version
        deletion, and provenance explanation payloads and results.
      - [x] Bind event, proposal, checkpoint, and disclosure payloads/results.
      - [x] Bind cursor-based sync pull/push payloads and results.
    - [x] Publish and verify the complete HTTPS OpenAPI surface.
  - [ ] Add cross-implementation conformance fixtures.
    - [x] Publish a versioned machine-readable core profile covering discovery,
      authentication, exact scopes, idempotency, tenant isolation, optimistic
      deletion, and ordered workspace-scoped sync.
    - [x] Publish a strict language-neutral lifecycle fixture corpus and make
      the black-box client consume it without embedding credentials or tenant
      identities.
    - [x] Emit a strict portable result containing the tested provider build
      and a pass record for every case in the selected profile.
    - [x] Add a secret-safe black-box HTTPS conformance runner.
    - [ ] Prove the runner against an independent local mock implementation.
      - [x] Add the independent mock and opt-in loopback CI execution hook.
      - [ ] Execute the loopback proof in a socket-enabled environment.
- [x] Versioned key-provider sidecar protocol for OS, HSM, and customer-KMS
  adapters.
  - [x] Add transport-independent Rust manifest, negotiation, request, context,
    and response-limit contracts to the offline verification gate.
  - [x] Add a secret-safe black-box HTTP conformance runner.
  - [x] Add a transport-neutral negotiated `RecordCipher` client with bounded
    requests and fail-closed response validation.
    - [x] Prevent request-correlation sequence exhaustion from wrapping and
      reusing identifiers.
  - [ ] Add an authenticated HTTP client adapter.
    - [x] Implement a redirect-free, proxy-free, bounded HTTPS and loopback
      HTTP transport with strict media-type, JSON, and base64 decoding.
    - [x] Add a dedicated Rust 1.88 test and warnings-as-errors CI job.
      - [x] Cover the configured cipher and its CLI, REST, and MCP consumers in
        the dedicated dependency-enabled gate.
    - [ ] Verify the dependency-enabled adapter build and tests in CI.
- [ ] TypeScript, Python, Rust, Swift, and Kotlin SDKs.
- [x] Reusable semantic-provider conformance suite.
- [x] Evidence-backed provider compatibility registry schema and initial
  native-provider record.
- [x] Expose the build-pinned compatibility registry through the CLI.
- [x] Run installed native-provider conformance through the CLI.
- [ ] Automated external-provider registry verification and release signing.
- [ ] WhatsApp Business gateway.
- [ ] Mobile share flows and iMessage extension.
- [ ] Community provider and agent adapters.

## Release gates

No stable release until:

- [x] Tenant-isolation tests cover every implemented adapter and transport
  read path.
- [x] Threat model and recovery model are published.
- [x] Protocol and encrypted export formats are versioned.
- [ ] Security-sensitive code has independent review.
- [x] Backup, restore, migration, revocation, and deletion have executable
  local-alpha coverage.
