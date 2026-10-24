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
  - [x] Add Windows DPAPI and Linux Secret Service adapters.
    - [x] Resolve active and historical Linux Secret Service keys through the
      fixed `secret-tool` client with lookup metadata only and zeroized output.
      - [x] Bind each lookup to service, account, and expected key ID to avoid
        cross-generation resolution through reused account metadata.
    - [x] Add a Windows DPAPI adapter.
      - [x] Define bounded generation-specific DPAPI blob references using
        local absolute paths, traversal rejection, and a Windows CI gate.
      - [x] Resolve active and historical CurrentUser keys through a fixed
        system PowerShell bridge with key-ID entropy and zeroized output.
      - [x] Exercise a live DPAPI protect/unprotect round trip in Windows CI.
  - [x] Define a vendor-neutral authenticated key-provider operation protocol
    that never exports raw workspace keys.
    - [x] Negotiate optional workspace-rotation capability and validate
      transport receipts against exact request, provider, workspace,
      generation, and recipient correlation.
    - [x] Bind rotation to the authenticated HTTP protocol and black-box
      provider conformance runner without exposing key material.
  - [ ] Resolve or unwrap keyring material through customer KMS adapters.
    - [x] Define the customer-sidecar trust boundary and AWS, Azure, and GCP
      mappings without giving Rembrane cloud credentials or master keys.
  - [x] Add a provider-agnostic configured cipher that dispatches to local
    environment/macOS keyrings or a policy-negotiated HTTP key provider.
    - [x] Accept consumed customer key-provider configuration from
      application-owned vault and cloud-secret resolvers without fixed
      environment-variable names.
    - [x] Zeroize key-provider bearer credentials across configuration,
      validation failure, transport construction, and teardown.
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
    - [x] Preserve those HTTP outcomes through session establishment,
      per-request reauthentication, cross-tenant replay denial, and
      authenticated termination.
    - [x] Add a framework-neutral HTTP gate that validates the session header,
      calls the hardened lifecycle before SDK dispatch, and emits bounded
      401/403/409/503 response policy with an RFC 9728 bearer challenge.
    - [x] Require an explicit bounded `Host` allowlist at the outer gate to
      reject DNS-rebinding traffic before authentication or MCP dispatch.
    - [x] Derive the accepted public Host authority and RFC 9728 challenge from
      the same validated remote-resource profile so deployment values cannot
      drift independently.
    - [x] Authorize modern stateless Streamable HTTP requests without accepting
      a legacy session identifier, while preserving per-request bearer,
      origin, host, method, tool, and scope enforcement.
    - [x] Classify bounded JSON-RPC bodies before SDK dispatch, rejecting
      batches, malformed envelopes, unsupported methods, and unknown or
      mismatched tool calls without trusting request headers.
    - [x] Couple stateless body classification and OAuth authorization in one
      gate operation so dispatched bytes cannot drift from the authorized
      method, tool, or scope.
      - [x] Return one opaque authorized-request object carrying verified
        access, operation classification, and the exact zeroizing body buffer.
    - [x] Adapt Axum header maps and HTTP rejection responses at the outer
      boundary, rejecting duplicate security headers before SDK dispatch.
    - [x] Provide an owned Axum authorization service that reconstructs
      borrowing authenticators per request and preserves verified tenant
      identity through an in-memory HTTP router.
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
    - [x] Prove the Axum boundary preserves distinct verified workspace
      identities and rejects an untrusted browser origin over HTTP routing.
  - [x] Add a hardened Cloudflare Tunnel Compose overlay that keeps persistent
    memory and encryption credentials on the operator-controlled origin.
- [x] Persist a disclosure receipt for every SQLite context response.
- [x] Require every future context storage adapter to implement disclosure
  persistence through compile-time composite repository capabilities.
- [x] Prove cross-tenant denial across SQLite user-facing read paths.
- [x] Require workspace identity for internal projection-job lookups.
- [ ] Prove cross-tenant denial across every future adapter read path.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.
  - [x] Add deny-by-default forced RLS policy generation for every canonical
    `workspace_id` table plus explicit workspace and share-proposal policies.
  - [x] Document transaction-local tenant identity and non-owner,
    non-`BYPASSRLS` runtime-role requirements.
  - [x] Run a live PostgreSQL two-tenant CI proof covering scoped reads,
    denied cross-tenant writes, and fail-closed missing tenant context.
  - [ ] Implement the Rust PostgreSQL repository adapter and live two-tenant
    integration suite.

## Phase 2 — Development continuity

- [x] Canonical temporal knowledge graph.
  - [x] Define engine-neutral, typed workspace-scoped nodes and relationships
    with separate event/system time, validity windows, provenance, bounded
    aliases, and explicit supersession references.
  - [x] Add tenant-isolated mutation and neighbourhood repository contracts
    with bounded temporal traversal and optimistic version checks.
  - [x] Add local SQLite graph persistence and Graphiti projection adapter.
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
    - [x] Process graph projections from exact canonical versions with
      retry/quarantine handling.
    - [x] Commit canonical graph mutations and projection jobs atomically.
      - [x] Define the atomic application repository contract.
      - [x] Implement the in-memory transaction adapter.
      - [x] Implement the SQLite transaction adapter.
    - [x] Add Graphiti projection adapter.
      - [x] Define a versioned, bounded sidecar protocol with workspace-derived
        namespaces, mutation idempotency, and response correlation.
      - [x] Implement the transport-injected Graphiti graph provider.
      - [x] Add authenticated bounded HTTP transport with strict origin,
        credential, timeout, redirect, response-size, manifest, and response
        correlation validation.
      - [x] Add executable Graphiti sidecar contract and integration tests.
        - [x] Implement and test a dependency-free contract core for workspace
          isolation, physical identity, idempotency, optimistic versions,
          temporal traversal, and bounded deletion.
        - [x] Bind the contract core to authenticated, body-bounded FastAPI
          endpoints that fail startup without an explicit bearer secret.
        - [x] Add a Neo4j-backed Graphiti persistence driver with deterministic
          tenant-scoped UUIDs, exact canonical metadata codecs, optimistic
          projection semantics, and environment-only provider credentials.
        - [x] Package an unprivileged loopback-only sidecar and private Neo4j
          deployment overlay using operator-supplied environment secrets.
        - [x] Add a gated live-sidecar runner and exercise the Rust HTTP
          adapter through the shared graph-provider conformance suite in CI.
        - [x] Add environment-selected native/Graphiti provider composition
          with explicit plaintext-processing opt-in and secret-local HTTP
          credentials.
        - [x] Add a configured encrypted SQLite graph-worker executable that
          drains provider-specific jobs through the canonical retry,
          supersession, completion, and quarantine state machine.
        - [x] Package the graph worker in the self-hosted Graphiti deployment
          with the shared encrypted volume, private sidecar endpoint, and
          operator-supplied credentials.
        - [x] Add a process-level worker lifecycle test that atomically seeds
          an encrypted SQLite graph node and outbox job, runs the configured
          worker once, and verifies persisted completion.

- [x] Project entities and scoped preferences.
- [x] Layer global, domain, entity, and activity context in one request.
- [x] Activity-scoped work-trace ingestion as proposed observation memory.
- [x] Model activity checkpoints and resumable handoffs.
- [x] Deterministic local Git state fingerprints for coding-agent handoffs.
- [x] Secret-safe Codex and Claude Code stdio MCP configuration generators.
- [x] Versioned vendor-neutral stdio connection manifest for apps, bots, and
  agent launchers.
- [x] Additional native coding-agent configuration adapters.
  - [x] Generate a secret-safe Gemini CLI `settings.json` MCP fragment.
  - [x] Generate secret-safe Cursor, VS Code, and Zed stdio MCP fragments.
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
- [x] Private-to-shared memory proposals.
  - [x] Content-free, exact-source-version proposal aggregate with source-owner
    approval, rejection, and pre-approval revocation.
  - [x] Tenant-scoped SQLite persistence with exact-source and workspace-kind
    constraints.
  - [x] Versioned canonical audit events and approved target-copy construction.
  - [x] Dual-workspace authorization and atomic in-memory reference transaction.
  - [x] SQLite atomic approval and target-workspace copy implementation.
  - [x] Verify the dependency-enabled SQLite integration suite in the complete
    workspace CI gate.
- [x] Authorized member removal with atomic scope-grant cleanup.
- [x] Group key rotation after membership changes.
  - [x] Define a content-free canonical rotation requirement with monotonic
    workspace generation and opaque completed-key identity.
  - [x] Create the requirement atomically with membership removal and scope
    revocation in in-memory and SQLite repositories.
  - [x] Deny new shared-workspace client grants while rotation is required.
  - [x] Complete exactly one pending generation through an owner/admin command
    after deployment-owned key-provider orchestration returns an opaque key
    identity.
  - [x] Extend the key-provider protocol with a verifiable rotation receipt
    binding generation and authorized recipients.
    - [x] Define a bounded content-free provider receipt with provider,
      correlation, workspace, generation, opaque key, and canonical recipient
      identities.
    - [x] Expose tenant-scoped canonical active-membership enumeration for
      exact recipient-set validation.
    - [x] Require receipt workspace and generation equality plus exact
      canonical active-recipient equality before completing rotation.
    - [x] Persist validated provider/request/key metadata and exact recipients
      atomically with rotation completion.
    - [x] Transport rotation requests and strictly decoded receipts over the
      authenticated bounded HTTP adapter with replay conformance coverage.
    - [x] Orchestrate provider rotation and completion through the management
      API and CLI.
      - [x] Add authorization-first application orchestration and a configured
        provider CLI command.
      - [x] Add the authenticated management REST operation.
      - [x] Prove unauthorized callers cannot trigger provider side effects
        and removed members are excluded from the provider recipient set.
- [x] Organizational audit and retention controls.
  - [x] Define an immutable bounded content-free administrative audit event
    contract with tenant, actor, closed action, opaque target, request
    correlation, and occurrence time.
  - [x] Persist administrative audit events append-only and tenant-scoped.
  - [x] Record membership, scope, key-rotation, retention, and legal-hold
    mutations atomically with their administrative audit evidence.
    - [x] Commit member removal, rotation requirement, and rotation completion
      with their audit evidence in the same repository transaction.
    - [x] Commit scope-grant and scope-revocation mutations with their audit
      evidence in the same repository transaction.
    - [x] Commit retention-policy and legal-hold mutations with their audit
      evidence in the same repository transaction.
  - [x] Define enforceable per-workspace retention policies and legal holds.
    - [x] Define versioned resource-specific retention periods, bounded expiry
      calculation, minimum audit/disclosure relationship, and legal-hold purge
      override semantics.
    - [x] Persist policies and legal holds with optimistic versioning.
    - [x] Execute bounded purge plans without deleting held resources or
      append-only security evidence prematurely.
  - [x] Expose narrowly authorized audit and retention management APIs.
    - [x] Add owner/admin-only application services for retention-policy and
      legal-hold mutation.
    - [x] Expose authenticated management HTTP and CLI operations.

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
  - [x] Add cross-implementation conformance fixtures.
    - [x] Publish a versioned machine-readable core profile covering discovery,
      authentication, exact scopes, idempotency, tenant isolation, optimistic
      deletion, and ordered workspace-scoped sync.
    - [x] Publish a strict language-neutral lifecycle fixture corpus and make
      the black-box client consume it without embedding credentials or tenant
      identities.
    - [x] Emit a strict portable result containing the tested provider build
      and a pass record for every case in the selected profile.
    - [x] Add a secret-safe black-box HTTPS conformance runner.
    - [x] Prove the runner against an independent local mock implementation.
      - [x] Add the independent mock and run it unconditionally in the
        dedicated Memory Provider CI job.
      - [x] Execute the loopback proof in the socket-enabled Memory Provider
        CI job.
  - [x] Add an authenticated Rust HTTP client adapter.
    - [x] Add bounded redirect-free, proxy-free HTTPS/loopback discovery with
      zeroized bearer credentials.
      - [x] Keep public discovery credential-free and attach bearer authority
        only to protected operation requests.
    - [x] Use canonical direct HTTPS operation bodies and results while
      binding request and protocol correlation exclusively through mandatory
      transport headers.
      - [x] Add socket-level Rust integration coverage for direct mutation
        bodies and bodyless percent-encoded GET operations.
    - [x] Reject manifests whose capability, OAuth scope, HTTP method, or path
      bindings differ from the canonical protocol registry.
    - [x] Add typed codecs and response validation for every operation.
      - [x] Resolve bounded global, domain, entity, or activity context and
        reconstruct canonical provenance, sensitivity, constraints, context
        pack, and disclosure identity.
      - [x] Submit idempotent evidence-backed memory proposals without tenant
        identity or caller-asserted confirmation.
      - [x] Delete one exact memory revision through a percent-encoded,
        path/payload-bound identifier and validate the consecutive tombstone
        result.
      - [x] Explain one exact memory revision with bounded immutable evidence
        references, without exposing raw sources or provider-internal
        reasoning.
      - [x] Resolve bounded questions into evidence-grounded answers carrying
        exact supporting revisions, context-pack identity, and disclosure
        identity.
      - [x] Record bounded idempotent event batches without caller-controlled
        tenant or actor identity and validate exact ordered result cardinality.
      - [x] Create or optimistically update resumable activity checkpoints
        through a safely encoded activity path and require consecutive result
        versions.
      - [x] Append purpose-bound disclosure receipts for exact memory
        revisions without caller-controlled workspace, subject, or client
        identity.
      - [x] Pull bounded, strictly ordered sync pages from opaque
        connection-bound cursors while validating resource, operation,
        payload, digest, and continuation invariants.
      - [x] Push idempotent optimistic mutation batches atomically from a base
        cursor and require ordered one-for-one canonical acknowledgements.
  - [x] Add deployment-selected Memory Provider composition using
    environment-owned endpoint and bearer-token values plus safe request
    identity prefixes.
    - [x] Accept consumed HTTP configuration values from application-owned
      keychains, vaults, cloud secret managers, and other secret resolvers
      without requiring fixed environment-variable names.
      - [x] Zeroize bearer material on configuration and transport error paths
        as well as normal client teardown.
    - [x] Expose every portable operation through a typed facade that always
      creates capability-checked requests from the negotiated connection
      before transport.
    - [x] Document secret-safe self-hosted configuration, connection policy,
      provider requirements, and conformance execution.
    - [x] Add a content-free CLI check that reports negotiated provider
      identity, privacy mode, capabilities, domains, and limits without
      exposing credentials.
    - [x] Require end-to-end encryption by default and explicit operator
      selection before accepting trusted-boundary or plaintext providers.
  - [x] Define an object-safe transport-neutral Rust client boundary covering
    every portable operation and implement it for the authenticated HTTP
    transport.
    - [x] Include discovery and policy negotiation, and let configured
      composition own any boxed client implementation.
- [x] Versioned key-provider sidecar protocol for OS, HSM, and customer-KMS
  adapters.
  - [x] Add transport-independent Rust manifest, negotiation, request, context,
    and response-limit contracts to the offline verification gate.
  - [x] Add a secret-safe black-box HTTP conformance runner.
  - [x] Add a transport-neutral negotiated `RecordCipher` client with bounded
    requests and fail-closed response validation.
    - [x] Prevent request-correlation sequence exhaustion from wrapping and
      reusing identifiers.
  - [x] Add an authenticated HTTP client adapter.
    - [x] Implement a redirect-free, proxy-free, bounded HTTPS and loopback
      HTTP transport with strict media-type, JSON, and base64 decoding.
    - [x] Add a dedicated Rust 1.88 test and warnings-as-errors CI job.
      - [x] Cover the configured cipher and its CLI, REST, and MCP consumers in
        the dedicated dependency-enabled gate.
    - [x] Verify the dependency-enabled adapter build and tests in the
      configured-encryption CI job.
- [x] TypeScript, Python, Rust, Swift, and Kotlin SDKs.
  - [x] Publish and test a zero-dependency TypeScript client package for the
    authenticated REST surface.
  - [x] Publish and test a standard-library-only Python client package for the
    authenticated REST surface.
  - [x] Publish the transport-neutral Rust provider SDK and authenticated HTTP
    implementation.
  - [x] Publish and compile-test a Swift Package with injectable async
    transport and a redirect-rejecting URLSession implementation.
  - [x] Publish a dependency-free Kotlin/JVM client package with injected
    transport and an executable smoke fixture.
    - [x] Execute the Kotlin compiler smoke fixture in a pinned Ubuntu 24.04
      CI environment that fails if `kotlinc` or Java is unavailable.
- [x] Reusable semantic-provider conformance suite.
- [x] Evidence-backed provider compatibility registry schema and initial
  native-provider record.
- [x] Expose the build-pinned compatibility registry through the CLI.
- [x] Run installed native-provider conformance through the CLI.
- [x] Automated external-provider registry verification and release signing.
  - [x] Verify registry identity, timestamps, conformance status, and pinned
    native Git evidence in the repository static gate.
  - [x] Produce and tamper-test detached Ed25519 signatures using an
    externally supplied private key.
  - [x] Publish signed registry artifacts from published GitHub releases using
    a repository-secret Ed25519 key and an ephemeral mode-restricted key file.
  - [x] Require a passing conformance result before any external provider can
    be promoted to compatible.
  - [ ] Add the first external provider only after its disposable-namespace
    conformance run produces reviewable evidence.
- [x] WhatsApp Business gateway.
  - [x] Verify webhook HMAC-SHA256 over the raw bounded payload before parsing
    and derive keyed pseudonymous sender/account lookup identifiers.
  - [x] Connect verified text events to atomic canonical sender admission while
    treating authenticated duplicate deliveries idempotently.
  - [x] Reject signed webhook events older than a deployment-owned maximum age
    before any batch storage mutation.
  - [x] Define a framework-neutral webhook HTTP policy with constant-time
    subscription verification, bounded challenges, and non-enumerating sender
    rejection outcomes.
  - [x] Ship a narrowly scoped Axum gateway binary that receives the channel
    database, deployment-owned WhatsApp secrets, and only the record-cipher
    capability needed to seal its durable inbox.
  - [x] Package the gateway as an opt-in hardened Compose overlay with a
    loopback-only host port and documented TLS proxy boundary.
  - [x] Add administrator-only sender onboarding that consumes raw identifiers
    and the lookup secret from protected environment variables and persists
    only matching keyed pseudonyms.
  - [x] Commit content-free administrative audit evidence atomically with
    explicit channel-binding creation and revocation.
  - [x] Exercise the executable webhook path in-process across signature
    verification, active sender resolution, SQLite replay admission, and
    idempotent duplicate delivery.
  - [x] Define the encrypted tenant-scoped channel inbox schema and application
    ports required for atomic admission, recovery, and completion.
  - [x] Atomically seal admitted channel text into SQLite with replay
    reservation, authenticated tenant-scoped recovery, and monotonic delivery
    completion.
  - [x] Make the executable gateway acknowledge new messages only after
    encrypted durable admission succeeds.
  - [x] Define a bounded provider-neutral inbox worker that completes messages
    only after an idempotent bot or agent processor succeeds.
  - [x] Add a strict authenticated HTTP processor adapter for pluggable bot and
    agent endpoints with canonical identity and event idempotency metadata.
  - [x] Add a configured per-workspace channel worker executable for encrypted
    inbox recovery, retry, HTTP processor delivery, and completion.
  - [x] Package ingress and delivery workers together in the opt-in hardened
    WhatsApp Compose profile.
  - [x] Persist bounded delayed delivery retries and quarantine poison messages
    after a deployment-configured maximum attempt count.
  - [x] Atomically lease encrypted inbox messages so concurrent workers cannot
    dispatch the same event, while expired claims are safely recoverable.
  - [x] Bind delivery completion, retry, and quarantine to a cryptographically
    random lease owner so stale workers cannot finalize reclaimed messages.
  - [x] Require every channel processor to declare a hard call-time bound and
    size leases for the entire claimed batch before any delivery begins.
  - [x] Expose administrator-authorized content-free inbox health counts through
    the CLI without granting message-content access.
  - [x] Allow an administrator to requeue one quarantined event by opaque
    channel/event identity with an atomic append-only audit record.
  - [x] Fingerprint opaque channel event identities into bounded,
    domain-separated content-free audit targets.
  - [x] Define a bounded authenticated-channel message contract whose
    canonical workspace, principal, and client identity must come from a
    deployment-owned sender binding rather than webhook payload claims.
  - [x] Add bounded per-channel replay protection with future-time rejection,
    capacity limits, expiry, and cross-platform event-ID namespaces.
  - [x] Persist content-free channel replay receipts in SQLite with atomic
    multi-process capacity enforcement and cross-workspace replay denial.
  - [x] Add privacy-safe sender bindings using keyed opaque account and sender
    lookup identifiers instead of storing WhatsApp phone numbers.
  - [x] Require an active canonical membership for every sender binding and
    revoke bindings automatically when that membership becomes inactive.
  - [x] Resolve active sender identity and reserve replay protection in one
    atomic storage transaction to prevent membership-revocation races.
- [x] Mobile share flows and iMessage extension.
  - [x] Reuse the authenticated-channel contract for explicit iMessage
    extension and mobile-share ingestion without claiming conversation
    interception.
  - [x] Add a strict signed-envelope adapter for explicit mobile shares with
    bounded content, pseudonymous device binding, freshness checks, and
    durable encrypted-inbox admission.
  - [x] Add administrator-authorized CLI enrollment and revocation for mobile
    devices without persisting raw account identifiers, device identifiers, or
    lookup secrets.
  - [x] Expose the signed mobile-share boundary through a narrowly scoped
    companion HTTP service.
  - [x] Package the mobile-share gateway in a loopback-only hardened Compose
    overlay with no broad memory API credential or default principal.
  - [x] Extend the Swift package with an injectable device-held signer and
    explicit-share client that targets the narrow gateway without a memory API
    bearer token.
  - [x] Publish a versioned implementation-independent OpenAPI contract and
    secret-free fixture for third-party companion apps and share extensions.
  - [x] Provide a CryptoKit HMAC signer compatible with Keychain-provisioned
    iOS companion and share-extension deployments.
  - [x] Provide one reusable bounded Swift Keychain enrollment store with
    optional explicit access-group support for companion and extension
    targets.
    - [x] Support validated device-only upsert and idempotent local revocation
      for companion-app enrollment flows.
    - [x] Generate bounded signing secrets from the operating system secure
      random source directly on the enrolled Apple device.
    - [x] Store enrollment as one versioned atomic Keychain bundle while
      retaining read migration and revocation cleanup for pre-alpha
      three-item installations.
  - [x] Provide a reusable Swift explicit-share coordinator that preflights
    selected text and opaque identifiers, generates event IDs, and submits only
    user-confirmed envelopes through the narrow signed gateway client.
  - [x] Publish a public-API-only iOS Share Extension reference controller with
    single-text selection, Keychain-held enrollment material, and explicit
    limitations against Messages database or background access.
  - [x] Publish a public-API-only Messages app extension reference that
    requires explicit text entry and confirmation without transcript,
    participant, composer, attachment, or background access.
- [ ] Community provider and agent adapters.
  - [x] Add a transport-injectable Mem0 OSS semantic mapping layer with
    pseudonymous workspace partitions, exact canonical ID/version metadata,
    replacement, bounded search, and version-aware deletion semantics.
    - [x] Add an authenticated, redirect-free, proxy-free, bounded HTTP
      transport for Mem0 OSS exact add, list, search, and deletion operations.
      - [x] Permit plaintext HTTP only for literal loopback IP addresses,
        rejecting remappable local hostnames consistently across sidecars.
    - [x] Expose disposable Mem0 conformance through the CLI with environment
      secret custody and an explicit plaintext-processing acknowledgement.
      - [x] Require a bounded safe external namespace with enough room for a
        fresh random suffix before any provider credential is resolved.
  - [ ] Add a Supermemory v5 semantic adapter with HMAC-derived namespaces,
    deterministic document identity, processing convergence, exact deletion,
    and shared disposable-provider conformance.
    - [x] Define the v5 API mapping, asynchronous replacement contract,
      plaintext boundary, and compatibility evidence requirements.
    - [x] Add a typed bring-your-own Supermemory connection profile using
      secret references and literal-IP-only loopback policy.
    - [x] Add a transport-injectable canonical mapping layer passing the
      shared semantic-provider conformance suite.
      - [x] Derive deterministic provider document IDs inside the trusted
        adapter so transports never choose or expose canonical identity.
      - [x] Domain-separate workspace and document HMAC pseudonyms.
      - [x] Validate generated namespaces against Supermemory's documented
        length and character contract.
      - [x] Keep canonical memory IDs out of provider paths by validating
        deterministic keyed document pseudonyms.
      - [x] Replace versions through deterministic provider upsert without a
        bounded pre-delete list scan.
        - [x] Serialize the current v5 caller-defined `id` field and require a
          bounded, exact-identity, non-failed ingestion acceptance response.
        - [x] Use exact retrieval followed by v5 PATCH for existing documents,
          reserving append-capable POST for first creation.
      - [x] Use exact deterministic document lookup for version-bounded
        deletion instead of scanning paginated namespace lists.
        - [x] Lock the no-list lifecycle invariant with regression coverage
          across preserved and deleted version bounds.
        - [x] Remove namespace enumeration from the trusted transport contract
          once exact identity covers every lifecycle operation.
      - [x] Require bounded readiness confirmation after ingestion before an
        adapter may report projection success.
        - [x] Bind readiness verification to the exact authorized projection
          for scoped search convergence.
        - [x] Serialize the current v5 `query` field for readiness and recall
          rather than the legacy `q` spelling.
        - [x] Request v5 instant processing for create and replacement so the
          bounded convergence window does not depend on dynamic batching.
      - [x] Strictly decode bounded search records and exact partial-
        deletion outcomes before connecting the HTTP client.
        - [x] Decode internal and caller-defined document identities
          independently and prefer the deterministic caller ID.
    - [x] Add an authenticated, redirect-free, proxy-free, bounded HTTP
      transport with scoped convergence polling and confirmed deletion.
    - [x] Expose disposable Supermemory conformance through the CLI with
      environment-only secrets and explicit plaintext acknowledgement.
      - [x] Require exact provider-identity confirmation before replacement or
        deletion can complete.
  - [x] Generate a secret-reference-only local MCP configuration for OpenCode
    using its command-array and environment-substitution contract.
  - [x] Enforce one bounded control-free executable-command contract before
    rendering any supported agent's TOML or JSON MCP configuration.
  - [x] Encode bounded control-free command and argument invariants in the
    implementation-independent stdio connection manifest schema.

## Release gates

No stable release until:

- [x] Provide one strict production-readiness command that fails on unavailable
  dependency, Postman, PostgreSQL, or container gates rather than skipping.
- [x] Run scheduled and change-triggered CodeQL analysis for Rust,
  JavaScript/TypeScript, and Python.
- [x] Reject pull requests introducing moderate-or-higher known dependency
  vulnerabilities or incompatible strong-copyleft/server-side licenses.
- [x] Fail static checks on risky CI triggers, write-all permissions,
  self-hosted runners, mutable action branches, download-and-execute pipes,
  unexpected write-capable workflows, or common committed token formats.
- [x] Tenant-isolation tests cover every implemented adapter and transport
  read path.
- [x] Threat model and recovery model are published.
- [x] Protocol and encrypted export formats are versioned.
- [ ] Security-sensitive code has independent review.
- [x] Backup, restore, migration, revocation, and deletion have executable
  local-alpha coverage.
