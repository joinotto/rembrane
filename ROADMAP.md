# Rembrane Roadmap

This roadmap describes sequencing, not release dates.
The gate-driven first-release execution plan and conditional timing estimate
are in [First Production Release Plan](docs/PRODUCTION_PLAN.md).

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
  - [x] Redact semantic-provider projections, queries, candidate identities,
    and plaintext from diagnostics while retaining safe structural metadata.
  - [x] Redact knowledge-graph provider tenant, resource, and temporal query
    identities from diagnostics while retaining safe structural metadata.
  - [x] Redact Graphiti routing, correlation, namespace, and payload material
    from protocol diagnostics while retaining safe operation metadata.
  - [x] Redact memory-provider routing, correlation, discovery identity, and
    generic payload material from protocol diagnostics.
  - [x] Redact arbitrary provider-error details and legacy semantic-provider
    discovery identities from debug diagnostics.
    - [x] Add a static regression gate requiring reviewed redacted debug
      implementations for production provider SDK structs and generic errors.
  - [x] Redact canonical evidence identities from standalone provenance
    diagnostics while retaining the closed source class.
  - [x] Redact every canonical identifier newtype from debug output without
    changing explicit display or validated string access.
    - [x] Add a static regression gate requiring reviewed redacted debug
      implementations for canonical identifiers and domain structs.
  - [x] Redact canonical memory plaintext and identities from diagnostics while
    retaining safe structural lifecycle information.
  - [x] Enforce explicitly reviewed debug output for every production adapter
    struct, including adapters added after the initial security audit.
- [x] Authorize confirmed preference creation through an application use case.
  - [x] Redact plaintext, identities, scopes, grants, provenance, and provider
    routing from preference and memory-lifecycle command diagnostics.
  - [x] Redact arbitrary application validation details from debug output and
    interoperable MCP error responses.
  - [x] Enforce explicitly reviewed debug output for every production
    application struct, including future use cases and protocol boundaries.
- [x] Model correction and deletion lifecycle operations.
- [x] Redact source and target tenant routing, principals, clients, memory and
  proposal identities, target scope values, provenance, and event identities
  from cross-workspace sharing command diagnostics.
- [x] Define atomic memory, event, and projection mutations.
- [x] Define an opaque record-encryption boundary.
  - [x] Bound canonical ciphertext, key identifier, algorithm, and nonce
    metadata before encrypted payloads enter any storage adapter.
  - [x] Bound and canonicalize workspace and record identifiers before they
    become encryption associated data or customer-provider request metadata.
  - [x] Redact tenant identifiers, record identifiers, key identifiers,
    ciphertext, and nonce bytes from cryptographic debug output.
    - [x] Redact plaintext seal buffers, encrypted envelopes, request context,
      provider identity, versions, and algorithms from key-provider protocol
      diagnostics.
    - [x] Redact algorithm identifiers from encrypted-envelope diagnostics and
      enforce reviewed debug output across every cryptographic struct.
- [x] Define and verify the tenant-isolated SQLite schema.
- [x] Add versioned, idempotent SQLite schema initialization.
- [x] Configure bounded SQLite lock waiting and WAL concurrency.
- [x] Serialize canonical memory records with a versioned format.
- [x] Serialize canonical event records with a versioned format.
  - [x] Redact event-stream and payload resource identities from diagnostics
    while retaining closed event kinds and safe version metadata.
- [x] Serialize canonical checkpoint records with a versioned format.
- [x] Require an explicit cipher capability for encrypted SQLite memory APIs.
- [x] Implement authenticated, tenant-scoped SQLite memory reads.
- [x] Atomically persist encrypted memories, events, evidence, and projections.
- [x] Persist and optimistically update the SQLite provider projection outbox.
  - [x] Redact semantic and graph projection job, tenant, resource, and
    provider identities from diagnostics.
- [x] Persist encrypted activity checkpoints with their audit events.
- [x] Redact checkpoint payloads, tenant and activity identities, client
  grants, disclosure purposes, and event identities from application command
  diagnostics.
- [x] Audit every externally resumed checkpoint revision with a tenant-scoped
  disclosure receipt.
- [x] Atomically persist exact-version disclosure receipts in SQLite.
- [x] Prototype a portable XChaCha20-Poly1305 record-cipher adapter.
- [x] Define validated native, Mem0, and Graphiti connection profiles using
  secret references rather than stored credential values.
  - [x] Bound and validate portable environment, file, and external
    secret-manager references before storing configuration.
    - [x] Make secret references opaque with source-specific read-only
      accessors so integrations cannot construct unvalidated variants.
      - [x] Redact environment names, protected file paths, and external vault
        keys from standalone and composed configuration debug output.
      - [x] Redact provider endpoints and remote MCP resource, issuer, OAuth,
        client, authority, and trusted-origin values from composed deployment
        configuration diagnostics.
    - [x] Add a pluggable zeroizing resolver port plus a protected local
      environment and secret-file implementation.
      - [x] Resolve validated provider credential lists atomically from the
        caller's selected local or external resolver.
      - [x] Require explicitly reviewed diagnostics for local secret resolver
        implementations and enforce the boundary statically.
      - [x] Bind protected-file validation and bounded reads to one opened
        file identity, rejecting path replacement during resolution.
  - [x] Bound and deduplicate each provider profile's credential-reference
    list before any secret-manager resolution.
  - [x] Make validated provider profiles opaque so callers cannot bypass
    endpoint, placement, or credential-reference invariants.
- [x] Implement the encrypted local SQLite adapter.
  - [x] Create owner-only database and snapshot files, reject permissive or
    symbolic-link database paths, and open through SQLite no-follow mode.
    - [x] Prove active WAL and shared-memory sidecars remain owner-only while
      the canonical encrypted database is open.
    - [x] Remove newly created snapshot destinations on every failed backup
      preparation, encoding, write, or post-write validation path.
    - [x] Copy snapshots into an already opened no-follow SQLite connection
      and clean up destinations rejected by the platform path encoding.
    - [x] Bind protected-file preparation and SQLite opens to one device/inode
      identity, and preserve attacker-installed replacements during cleanup.
    - [x] Retain and synchronize the exact prepared database handle plus its
      parent directory before reporting initialization or backup success.
    - [x] Remove partial files after failed initialization of a new database
      while preserving every pre-existing database on startup failure.
- [x] Add development-key encrypted CLI remember and recall commands.
  - [x] Validate preference content, scope selectors, and client identities
    before opening tenant storage.
  - [x] Validate recall purpose, query, scope selectors, and client identity
    against provider-compatible bounds before opening tenant storage.
  - [x] Reject malformed and repeated memory-command value options before
    dispatch so an invalid explicit scope or version cannot become a default.
    - [x] Reject unrecognized flags, unsupported equals-value spellings, and
      stray positional arguments before storage so typos cannot broaden scope.
- [x] Expose exact-version proposal approval through the local encrypted CLI.
  - [x] Require explicit review attestation, matching scope, subject ownership,
    and canonical owner/admin confirmation permission.
  - [x] Return versioned, secret-safe confirmation results with schema
    fixtures and pre-storage input validation.
  - [x] Prove unapproved work traces are excluded from recall, approval retains
    observation provenance, and a fresh MCP client receives the confirmed
    version with a durable disclosure receipt.
  - [x] Reject denied, stale, repeated, wrong-key, and deleted-record approvals
    without changing canonical memory, evidence, or events.
- [x] Add encrypted CLI correction and deletion commands.
  - [x] Add structured, secret-safe correction and deletion results for
    cross-agent lifecycle synchronization.
  - [x] Prove structured correction and deletion success, stale-version
    rejection, version advancement, and secret-safe failures end to end.
  - [x] Preserve every canonical memory kind in lifecycle results and prove
    encrypted deletion of proposed observations returns the correct tombstone.
  - [x] Validate resume activity/client routing, disclosure purpose, and state
    fingerprint before opening tenant storage.
  - [x] Validate checkpoint routing, required create fields, list ceilings,
    scalar text, and aggregate payload size before opening tenant storage.
- [x] Create new local database, backup, and restore directory components with
  owner-only Unix permissions without modifying existing parent directories.
- [x] Create encrypted backup exports and restored databases atomically with
  owner-only permissions and durable file synchronization.
  - [x] Retain opened-file identity through export and restore validation,
    refusing destructive cleanup when a protected path is replaced.
  - [x] Read temporary snapshot size and contents through the same opened file
    and remove only that exact snapshot identity after export.
  - [x] Reject symbolic-link and non-regular export inputs, using no-follow
    nonblocking reads on Unix so special files cannot stall backup or restore.
  - [x] Synchronize Unix parent directories after export/restore creation and
    protected temporary-file removal before reporting durable completion.
- [x] Enforce provider-registry input bounds while streaming file contents,
  including files that change after metadata validation.
- [x] Add an executable encrypted CLI lifecycle smoke test.
- [x] Add Postman REST authentication and tenant-isolation smoke tests.
- [x] Add an MCP initialize/list/call protocol smoke test.
- [x] Prove encrypted cross-tool continuity from CLI to MCP and back, plus
  MCP-created project-checkpoint resumption by both a fresh agent process and
  the CLI.
- [x] Add a single full preflight test command and operator testing guide.
  - [x] Isolate disposable CLI/MCP/REST/cross-tool fixture configuration from
    inherited Rembrane provider, key-reference, identity, and permission
    settings while preserving documented binary/listen overrides.
    - [x] Test namespace-wide reset, future provider settings, no secret-value
      output, unchanged parent configuration, and lifecycle script wiring.
- [x] Expose authorized CLI recall as structured JSON for generic bots,
  launchers, and agent runtimes while preserving context-pack and disclosure
  receipt identity.
  - [x] Bound CLI recall to 100 items and 1 MiB before storage access.
  - [x] Return a generic JSON failure envelope without echoing query text,
    tenant routing, storage paths, or internal provider diagnostics.
- [x] Version CLI checkpoint and resume output so fresh agent processes can
  consume working-memory state through a stable protocol surface.
  - [x] Bound canonical checkpoint next-step and blocker collections to 1,024
    combined items in addition to the existing 256 KiB payload ceiling.
    - [x] Reject empty list entries and enforce the same collection ceiling at
      the external Memory Provider Protocol boundary.
    - [x] Reject NUL characters in canonical checkpoint goals, summaries, and
      state fingerprints consistently with the provider boundary.
    - [x] Bound canonical checkpoint routing identifiers to 255 safe ASCII
      characters consistently with the external provider protocol.
  - [x] Return closed checkpoint and resume failure envelopes without exposing
    working state, fingerprints, tenant routing, paths, or internal errors.
- [x] Expose work-trace capture as structured CLI success and secret-safe
  failure results for generic agents and bots.
  - [x] Reject unsafe routing IDs, empty/NUL summaries, and oversized trace
    content before opening tenant storage.
- [x] Expose confirmed preference capture as structured CLI success and
  secret-safe failure results for arbitrary assistants and bots.
- [x] Publish an executable local-alpha acceptance contract with independent
  static, Rust/E2E, and container CI gates.
- [x] Add a secret-safe local installation doctor command.
  - [x] Provide identity-minimizing structured doctor output for launchers,
    installers, agents, and bots without exposing principal or workspace IDs.
    - [x] Enforce the structured output and mixed-mode rejection in the
      canonical encrypted CLI lifecycle suite.
    - [x] Return a generic machine-readable failure envelope without exposing
      arbitrary storage, tenant, key, or provider diagnostics.
- [x] Report production-readiness prerequisites individually, including
  dependency resolution, loopback binding, PostgreSQL, and Docker capabilities.
- [x] Report local processing, connection scopes, endpoints, and secret sources
  through `rembrane doctor --privacy`.
- [x] Add encrypted SQLite backup and verified restore commands.
- [x] Add explicit plaintext JSONL export for authenticated canonical memories
  with deterministic ordering, closed versioned records, tenant checks,
  record/byte bounds, owner-only exclusive output, durable synchronization,
  and replacement-safe partial-file cleanup.
  - [x] Reject unsupported scope selectors and malformed/repeated portability
    options before I/O rather than silently exporting broader plaintext.
  - [x] Defer export directory creation until membership, format-specific
    authority, and encrypted-record authentication succeed.
- [x] Add authenticated import plus Markdown and graph portability formats.
  - [x] Expose authenticated REST exports for JSONL, Markdown, and owner/admin
    graph JSON with tenant binding, fixed attachment names, no-store and
    nosniff response policy, OpenAPI, and black-box protocol coverage.
  - [x] Expose typed and bounded portable REST exports through the TypeScript
    and Python SDKs with exact content metadata and JSON problem handling.
  - [x] Expose bounded atomic JSONL imports through the TypeScript and Python
    SDKs with optimistic sequence binding and closed response validation.
  - [x] Define a deterministic, bounded, provider-independent Markdown export
    with tenant/revision validation, stable ordering, provenance metadata, and
    content fences that remain safe when memories contain Markdown backticks.
  - [x] Expose Markdown through the authenticated CLI export path with explicit
    plaintext consent, exclusive owner-only output, durable persistence, and
    tenant-scope enforcement.
  - [x] Define a deterministic, bounded, provider-independent graph archive
    preserving nodes, edges, temporal validity, evidence, revisions, and
    supersession while rejecting mixed workspaces and dangling endpoints.
  - [x] Add a bounded canonical graph-snapshot repository port with
    tenant-filtered in-memory and authenticated encrypted-SQLite adapters.
    - [x] Implement the same snapshot port in the RLS-bound PostgreSQL adapter
      with one tenant transaction, bounded node/edge reads, and authenticated
      record decryption.
  - [x] Expose owner/admin-only whole-workspace graph JSON export through the
    CLI with explicit plaintext consent and private durable output.
  - [x] Advertise implemented JSONL, Markdown, graph JSON, and encrypted
    archive exports through discovery with executable drift checks.
  - [x] Move the JSONL record contract into the provider-independent codec and
    add strict decoding with closed fields, exact format/version checks, domain
    invariant restoration, and a per-record byte ceiling.
  - [x] Provide whole-archive validation with fixed record/byte ceilings,
    homogeneous source tenancy, duplicate revision rejection, and no blank
    records so import surfaces can validate before canonical mutation.
  - [x] Apply validated JSONL imports as one authorized atomic canonical
    mutation, admitting external content as reviewable proposals rather than
    silently confirmed memory.
    - [x] Define a bounded import-as-proposals application use case and atomic
      repository port with destination scope authorization, fresh target
      identity checks, and contiguous canonical event construction.
    - [x] Implement the atomic port in the in-memory reference adapter.
    - [x] Implement the atomic port in encrypted SQLite, sealing every memory
      and event before one transaction and rolling back all earlier inserts
      when a later record conflicts.
    - [x] Implement the atomic port in the tenant-bound PostgreSQL adapter,
      validating and sealing the complete batch before one RLS-scoped
      transaction with one final commit.
    - [x] Expose protected-file JSONL import through the CLI with explicit
      plaintext acknowledgement, complete pre-mutation validation,
      destination scope authorization, and fresh target identities.
      - [x] Validate import client identifiers before reading archives and
        reject unsupported scope remapping rather than ignoring arguments.
      - [x] Prove encrypted CLI round-trip portability preserves source scopes
        as proposed records with imported provenance and fresh destination
        identities; malformed inputs leave memory and events unchanged.
    - [x] Expose authenticated JSONL import through the REST API using a
      route-specific bounded NDJSON body, exact content type, connection-bound
      destination identity, scope authorization, and the same atomic
      proposal-only service.
    - [x] Publish JSONL import capability through discovery and the portable
      OpenAPI contract.
    - [x] Prove the REST import boundary black-box: authentication, exact media
      type, malformed archives, tenant isolation, proposal-only admission,
      imported evidence, and contiguous event persistence.
- [x] Package the local REST service for loopback-only Docker Compose
  self-hosting with persistent encrypted storage.
  - [x] Construct synchronous provider clients outside the async executor and
    dispatch every authenticated canonical REST operation through bounded
    blocking workers without holding runtime locks on executor threads.
  - [x] Authenticate before worker admission, return documented 503 overload
    problems, and retain capacity until real completion after cancellation.
  - [x] Prove no-listener worker isolation, overload/failure cleanup, tenant
    denial, and encrypted remember/recall on a current-thread async runtime.
  - [x] Authorize canonical connection metadata before workspace cipher,
    rotation-provider, or graph-client initialization; preserve empty
    invitation/recovery grants without widening memory authority.
    - [x] Prove unknown/foreign/inactive identity rejection without provider
      initialization, single authorized startup, provider failure propagation,
      and the narrow invitation/pending-rotation startup modes.
  - [ ] Execute the refactored HTTP listener/Postman and load/recovery suites
    in a socket-enabled staging environment.
  - [x] Resolve the REST bearer credential from validated environment or
    protected-file references and enforce bounded RFC bearer-token grammar.
  - [x] Mount the REST bearer credential and development workspace key as
    owner-only Compose secrets without interpolating raw values into service
    environment metadata.
  - [x] Let least-privileged channel services skip personal-workspace
    bootstrap without receiving a default principal, while waiting for the
    canonical service to initialize shared storage.
  - [x] Make the canonical and channel-service container roots read-only with
    only encrypted state volumes and bounded temporary filesystems writable.
  - [x] Stage file-backed Compose secrets into an owner-only runtime tmpfs
    before dropping privileges so strict file validation does not depend on
    Compose implementations honoring secret ownership metadata.
  - [x] Report the effective workspace-key or key-provider credential source
    in privacy diagnostics, distinguishing protected reference targets from
    raw process-environment secrets.
- [ ] Add production OS-keychain and customer-KMS key providers.
  - [x] Honor environment or macOS Keychain selection uniformly in the CLI,
    REST API, and MCP server, including historical-key reads.
  - [x] Support active-key writes and historical-key reads through a
    duplicate-safe versioned record-cipher keyring.
    - [x] Bound local OS-backed keyrings to 1,024 total generations and reject
      unsafe key identifiers before cipher construction.
  - [x] Resolve a single active key from macOS Keychain without environment
    key material.
  - [x] Resolve active and historical rotating keyrings from macOS Keychain
    using metadata-only references.
    - [x] Publish the complete macOS Keychain lookup profile in the canonical
      environment template for local and Mac mini self-hosting.
  - [x] Add Windows DPAPI and Linux Secret Service adapters.
    - [x] Redact OS key identifiers, service/account lookup metadata, and
      protected DPAPI blob paths from debug output.
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
      - [x] Redact rotation request, workspace, and recipient identities from
        protocol diagnostics while retaining generation and recipient count.
      - [x] Apply the same redaction to persisted rotation receipts and
        workspace rotation lifecycle state.
      - [x] Reject unbounded or unsafe provider, workspace, and recipient
        identities before accepting a rotation receipt.
      - [x] Reject unsafe or unbounded lifecycle identities when creating,
        restoring, or completing a workspace key rotation.
      - [x] Reject unsafe or unbounded workspace and recipient identities
        before dispatching an outbound provider rotation request.
      - [x] Require bounded portable request identifiers for every
        key-provider operation before transport dispatch.
    - [x] Bound untrusted manifest algorithm collections and require closed
      portable algorithm identifiers before capability negotiation.
      - [x] Enforce the 1 MiB advertised plaintext ceiling in the core
        protocol for every transport implementation.
      - [x] Keep the normative OpenAPI schema aligned with all enforced
        provider manifest, request, context, envelope, and rotation bounds.
        - [x] Fail the static protocol gate when those normative bounds drift
          from the reviewed key-provider contract.
    - [x] Bind rotation to the authenticated HTTP protocol and black-box
      provider conformance runner without exposing key material.
      - [x] Keep provider-bound seal-request plaintext in redacted,
        zeroize-on-drop ownership throughout protocol dispatch.
      - [x] Explicitly wipe provider-returned plaintext before rejecting a
        response that exceeds the negotiated size boundary.
      - [x] Zeroize bounded raw key-provider responses after strict typed
        decoding.
      - [x] Emit a strict portable conformance result with provider identity
        and explicit evidence for all eight key-provider security cases.
        - [x] Publish strict machine-readable case requirements and derive
          runner evidence from the reviewed core profile.
          - [x] Bind every result schema, fixture, and runner output to the
            exact core profile identifier.
          - [x] Require result case identity and order to match the reviewed
            profile exactly.
          - [x] Bind portable evidence to the SHA-256 of the exact reviewed
            profile bytes.
            - [x] Reject evidence after profile bytes change even when the
              modified profile is rehashed into the compatibility lock.
        - [x] Bind discovery and conformance evidence to an exact bounded
          provider build version rather than identity alone.
  - [x] Resolve or unwrap keyring material through customer KMS adapters.
    - [x] Define the customer-sidecar trust boundary and AWS, Azure, and GCP
      mappings without giving Rembrane cloud credentials or master keys.
    - [x] Publish a provider-side wrapped-key adapter contract with bounded
      opaque references, tenant/generation associated data, duplicate-safe
      active and historical generations, and zeroizing unwrap results.
    - [x] Bridge customer-KMS keyrings into the reference record cipher with
      exact 256-bit key validation, active-generation writes, and historical
      decrypt support.
    - [x] Add AWS KMS, Azure Key Vault, and Google Cloud KMS bridge types over
      injectable customer-owned clients with explicit provider-specific
      authenticated-context binding and generation-substitution denial.
      - [x] Redact tenant context, provider key locators, wrapped keys, and
        authenticated-data bytes from customer-KMS diagnostics.
    - [x] Support customer-cloud data-key generation for rotation with exact
      256-bit plaintext enforcement, persistable wrapped references, and
      non-cloneable zeroizing plaintext ownership.
    - [x] Consume generated customer-KMS plaintext exactly once into the
      reference cipher while returning only its opaque wrapped reference for
      durable sidecar persistence.
    - [x] Require atomic compare-and-activate persistence of the strict next
      wrapped-key generation before releasing its zeroizing plaintext for
      sidecar cipher activation.
    - [x] Provide a durable SQLite sidecar key-reference store with
      per-workspace isolation, one active generation, historical references,
      and transactional stale-rotation denial.
      - [x] Support thread-safe shared worker access and prove concurrent
        attempts can activate only one successor generation.
      - [x] Bound historical keyrings and durable loads to 1,024 generations
        with explicit overflow rejection.
      - [x] Redact workspace identity from trusted recovery-floor diagnostics.
      - [x] Prove generate, persist-before-activate, reload, current decrypt,
        and historical decrypt as one executable sidecar rotation flow.
  - [ ] Record reviewable disposable-sidecar conformance evidence for AWS KMS,
    Azure Key Vault, and Google Cloud KMS before calling the providers
    production-ready.
      - [x] Define and verify a credential-free evidence envelope binding the
        exact provider build, disposable namespace, conformance result,
        explicitly approved IAM policy, core profile, and completed resource
        cleanup.
        - [x] Generate the envelope locally from reviewed artifacts and
          metadata without resolving or retaining cloud credentials.
        - [x] Verify an exact three-provider release set with distinct sidecar
          identities and disposable namespaces and no undeclared artifacts.
          - [x] Bound and structurally reject outer evidence documents before
            parsing provider identity at the release gate.
          - [x] Require that complete provider set in strict production
            readiness rather than treating external evidence as out of band.
        - [x] Bind a redacted cloud audit export so provider promotion proves
          the named KMS handled the disposable conformance operations.
          - [x] Reject common secret fields and recognizable credential
            material before accepting retained cloud audit evidence.
          - [x] Verify provider sets from exact no-follow artifact reads
            without reopening evidence across subprocess boundaries.
      - [x] Create file-backed Unix keyring databases owner-only and reject
        permissive, non-regular, or symbolic-link targets.
        - [x] Prove active keyring WAL and shared-memory sidecars remain
          owner-only while the customer sidecar database is open.
        - [x] Open keyrings, backup verification, and restore connections
          through SQLite no-follow mode after canonicalizing only the parent.
        - [x] Create backup and restore destinations atomically and clean up
          partial files after failed first-time keyring initialization.
        - [x] Copy backups and restores only between already hardened SQLite
          connections so convenience APIs cannot reopen mutable paths.
        - [x] Bind keyring preparation, verification, backup, and restore opens
          to one device/inode identity without deleting swapped-in files.
        - [x] Retain and synchronize the exact prepared keyring handle plus its
          parent directory before creation, backup, or restore reports success.
      - [x] Enforce workspace, provider-key, and wrapped-ciphertext bounds in
        both new and existing SQLite databases before row materialization.
      - [x] Create non-overwriting owner-only keyring backups and verify
        snapshot integrity and schema before reporting success.
      - [x] Restore only from verified owner-only snapshots into new
        destinations and re-verify before opening recovered keyrings.
        - [x] Require a complete bounded set of trusted per-workspace
          generation floors and reject rollback or workspace-set drift.
  - [x] Add a provider-agnostic configured cipher that dispatches to local
    environment/macOS keyrings or a policy-negotiated HTTP key provider.
    - [x] Accept consumed customer key-provider configuration from
      application-owned vault and cloud-secret resolvers without fixed
      environment-variable names.
    - [x] Zeroize key-provider bearer credentials across configuration,
      validation failure, transport construction, and teardown.
    - [x] Construct customer key providers from validated reference-only
      profiles through any deployment-selected secret resolver.
    - [x] Resolve the environment-driven HTTP key-provider credential from
      validated environment or protected-file reference metadata.
    - [x] Remove raw HTTP key-provider bearer interpolation from channel
      deployment overlays and enforce reference-only configuration.
    - [x] Resolve the local development workspace key from validated
      environment or protected-file reference metadata.
  - [x] Wire configured cipher selection through CLI, REST, MCP, generated
    agent configuration, and privacy diagnostics.
- [x] Retrieve minimal context through local stdio MCP.
  - [x] Prevent inbound MCP tool arguments from deriving plaintext-bearing
    debug output and enforce that invariant in the static security gate.
  - [x] Redact plaintext and identity data from shared context, graph, and
    disclosure contract diagnostics across every protocol surface.
- [x] Fail closed when REST or local MCP generated-identifier sequences are
  exhausted instead of reusing saturated memory, event, or disclosure IDs.
- [x] Require a representable strict successor for every optimistic record
  version and canonical event sequence across services and storage adapters.
- [x] Rank canonical context by deterministic local query relevance.
  - [x] Restrict native semantic, native graph, and volatile store diagnostics
    to collection counts and enforce the invariant statically.
- [x] Enforce administrator-configured connection read-scope allowlists.
- [x] Bind write permissions to exact administrator-configured scopes.
- [x] Create, correct, and delete authorized preferences through local MCP.
- [x] Create, update, and resume encrypted activity checkpoints through MCP.
- [x] Retrieve minimal context through authenticated local REST.
- [x] Create, optimistically update, and audit encrypted activity handoffs
  through REST, OpenAPI, and the TypeScript and Python SDKs.
- [x] Create, correct, and delete confirmed scoped preferences through REST,
  OpenAPI, and path-safe TypeScript and Python SDK methods.
- [x] Record evidence-backed activity work traces as proposed observations
  through REST, OpenAPI, and the TypeScript and Python SDKs.
- [x] Redact imported memory plaintext, identities, scopes, provenance, and
  grants from application import diagnostics.
- [x] Serve unauthenticated, credential-free REST capability discovery with
  deployment-accurate API location, privacy mode, limits, and handoff support.
- [x] Fetch public capability discovery through the TypeScript and Python SDKs
  without transmitting the configured bearer credential.
- [x] Fail SDK discovery closed on malformed capabilities, privacy metadata,
  protocol versions, or an advertised API root that differs from the
  configured endpoint.
- [x] Publish closed discovery privacy types in both SDKs and reject unknown
  plaintext-processing locations before provider selection.
- [x] Reject malformed optional discovery capabilities, import/export format
  lists, and resource limits before provider selection.
- [x] Enforce closed discovery objects, HTTPS OAuth endpoints, absolute MCP
  endpoints, bounded provider metadata, and namespaced extension keys in SDKs.
- [x] Prove both SDKs accept the canonical full discovery fixture without
  transmitting bearer credentials.
- [ ] Add remote Streamable HTTP MCP with OAuth.
  - [x] Authorize canonical MCP membership and rotation policy before workspace
    key/provider initialization using metadata-only storage.
    - [x] Prove unknown/foreign/inactive identity and pending-rotation rejection
      without provider calls, while preserving verified-request identity and
      encrypted tool continuity after authorized startup.
  - [x] Move all MCP tool storage/provider work and mutex acquisition onto
    process-shared bounded blocking workers, preserving the complete SDK
    request context and canonical authorization.
  - [x] Check immutable verified request identity before admission and retain
    worker capacity through real completion after abandoned requests.
    - [x] Reject elapsed remote startup and tool proofs before provider/worker
      admission and recheck lifetime with canonical tool authorization.
  - [x] Construct stdio providers outside the executor and expose bounded
    async constructors for stdio and verified remote service initialization.
  - [x] Prove actual in-memory SDK handshake/tool execution, encrypted
    preference continuity, verified proof preservation, overload/failure
    cleanup, and cancellation while waiting for canonical storage.
  - [x] Isolate synchronous OAuth verification in all owned/shared remote
    authorization-service async routes with process-shared bounded admission
    and capacity retained until real completion after abandonment.
    - [x] Keep registry locks out of verification and SDK awaits, preserve
      request-owned zeroizing bodies and 401/403 outcomes, and reject overload
      with a closed 503/Retry-After response before verifier/SDK execution.
    - [x] Advance the trusted request-time snapshot by monotonic elapsed whole
      seconds so worker scheduling or introspection cannot extend token expiry.
    - [x] Retain a non-renewable process-local validity deadline in verified
      proofs, including verification/worker scheduling time; clones preserve
      the deadline without changing claims or cache/session identity.
    - [x] Recheck proof lifetime around tenant construction and before/after
      Tower readiness; deny expired client POST/initialize/GET/DELETE routes.
    - [x] Reject elapsed session binding/commit and preserve exact-session
      compensating cleanup after initialization, releasing reserved capacity.
      - [x] Preserve validated Host/Origin for shared initialization/cleanup,
        and roll back failed compatibility initialization only with its exact
        unchanged binding, without granting expired client DELETE authority.
    - [ ] Verify live stream expiry/revocation and queued SDK tool denial in
      the actual remote listener; admission checks do not close opened streams.
      - [x] Retain the exact Tower service and original authority metadata
        through initialization commit/compensation so expiry pruning or cache
        replacement cannot redirect cleanup to a new factory-selected service.
      - [x] Prove original-service cleanup after pruning/replacement with a
        delayed Tower fixture; reject missing/type/identity/header substitution
        and bound retained selection through panic/cancellation completion.
      - [ ] Exercise concurrent expiry pruning and late initialization cleanup
        with actual SDK session state, not only generic Tower fixtures.
    - [x] Verify blocking-client executor isolation, per-request verification,
      shared budgets, all-route overload, failure cleanup, and cancellation.
    - [ ] Exercise the boundary with the actual official SDK remote listener
      and real HTTPS introspection in staging; low-level borrowing compatibility
      helpers still require caller-managed synchronous verifier execution.
  - [x] Define HTTPS endpoints, RFC 9728 discovery metadata, bearer challenges,
    verified connection identity, scope ceilings, and session security rules.
  - [x] Serve opt-in RFC 9728 protected-resource metadata from the HTTP
    service, requiring an exact HTTPS resource and authorization-server pair.
    - [x] Require the API metadata route to consume the complete validated
      introspection profile and advertise exactly its public `/mcp` resource.
    - [x] Validate and report that same complete profile through CLI privacy
      diagnostics without resolving or exposing its client credential.
  - [x] Add a fail-closed verified-token claims contract.
    - [x] Redact all identity, authority, scope, and lifetime claims from
      introspection diagnostics and enforce the boundary statically.
    - [x] Bound and reject ambiguous issuer, resource, audience, subject,
      client, and workspace claims in the transport-neutral verifier contract.
      - [x] Reject whitespace-bearing identity and authority claims before
        they can become canonical tenant bindings.
  - [x] Add a transport-independent authentication boundary backed by a
    signature-verifying or authenticated-introspection adapter.
  - [x] Add an RFC 7662 authenticated-introspection adapter with a
    replaceable bounded HTTP transport.
    - [x] Provide a concrete HTTPS transport with authenticated client
      credentials, strict timeouts, no redirects, and bounded responses.
      - [x] Reject query-bearing introspection endpoints and non-JSON
        successful claim responses.
      - [x] Apply canonical audience-cardinality, audience-size, and scope-size
        ceilings while decoding provider-controlled claims.
      - [x] Percent-encode the introspected bearer into a bounded
        zeroizing-owned form body without parameter-injection ambiguity.
      - [x] Zeroize the bounded raw claims response after typed decoding.
    - [x] Resolve client credentials through the deployment-selected secret
      resolver without fixed environment-variable names.
  - [x] Map every current MCP tool to one narrow OAuth scope and fail closed
    for unknown tools.
  - [x] Add transport-neutral HTTP authorization middleware with strict bearer
    parsing, trusted-origin checks, fail-closed tool lookup, and per-request
    reauthentication.
    - [x] Redact authorization, session, host, and origin values from
      remote-MCP HTTP request diagnostics.
    - [x] Redact verified claims, tenant identity, and session routing
      capabilities in shared remote-access contract diagnostics.
    - [x] Redact arbitrary factory, SDK, dispatch, initialization, and
      compensation errors at the remote-MCP adapter boundary.
    - [x] Redact validated transport metadata, initialized SDK output, and
      tenant-service cache identities from remote-MCP diagnostics.
      - [x] Redact invocation methods, tool names, and bearer challenges and
        statically reject derived debug output on remote-MCP HTTP structs.
    - [x] Reject oversized bearer credentials before signature verification or
      authenticated introspection work.
    - [x] Authenticate initialize, discovery, event-stream, and session-delete
      requests without granting a tool scope they did not request.
  - [x] Integrate the authorization middleware with the HTTP server adapter.
    - [x] Validate complete remote profiles before startup, including exact
      HTTPS endpoints, referenced client secrets, and exact browser origins.
      - [x] Parse and canonicalize deployment URLs while bounding endpoint,
        OAuth client, and trusted-origin list sizes.
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
      - [x] Deny stateless cancellation notifications until the official SDK
        transport can prove each target request belongs to the same verified
        tenant; session-bound cancellation remains separately authorized.
    - [x] Classify bounded JSON-RPC bodies before SDK dispatch, rejecting
      batches, malformed envelopes, unsupported methods, and unknown or
      mismatched tool calls without trusting request headers.
      - [x] Stream past private tool arguments during authorization
        classification instead of duplicating the complete parameter tree
        outside the zeroizing request body.
      - [x] Enforce SDK-compatible string or signed-integer IDs on request
        methods and forbid IDs on notification methods before OAuth dispatch.
    - [x] Couple stateless body classification and OAuth authorization in one
      gate operation so dispatched bytes cannot drift from the authorized
      method, tool, or scope.
      - [x] Return one opaque authorized-request object carrying verified
        access, operation classification, and the exact zeroizing body buffer.
    - [x] Couple established-session body classification, tenant
      reauthentication, and OAuth scope authorization into the same consuming
      exact-body proof used by the SDK dispatcher.
    - [x] Adapt Axum header maps and HTTP rejection responses at the outer
      boundary, rejecting duplicate security headers before SDK dispatch.
      - [x] Bound every security and MCP negotiation header before parsing or
        authentication work.
      - [x] Reject ambiguous duplicate content negotiation and MCP protocol
        version headers before authorizing the request body.
      - [x] Require JSON request content and explicit JSON plus event-stream
        response negotiation before OAuth evaluation.
      - [x] Restrict optional MCP protocol versions to bounded date-shaped
        tokens before preserving them for SDK dispatch.
    - [x] Provide an owned Axum authorization service that reconstructs
      borrowing authenticators per request and preserves verified tenant
      identity through an in-memory HTTP router.
      - [x] Expose exact-body session initialization and established-session
        dispatch through the owned service, including failed-initialize
        rollback.
      - [x] Expose downstream-confirmed session deletion through the owned
        service, retaining the tenant binding when SDK termination fails.
      - [x] Authorize stateless server event-stream GET requests with
        GET-specific negotiation and no artificial JSON content requirement.
        - [x] Return an owned GET proof coupling tenant identity, negotiated
          event-stream acceptance, and bounded protocol version.
        - [x] Add an asynchronous consuming event-stream dispatcher port for
          the official SDK transport.
          - [x] Preserve the validated public host and optional browser origin
            through the consuming event-stream dispatch handoff.
        - [x] Compose GET authorization and asynchronous stream dispatch in
          one operation with typed authorization-versus-transport failures.
    - [x] Provide a consuming dispatch handoff that keeps verified identity,
      classified invocation, and the exact zeroizing request body coupled
      until the official SDK transport takes ownership.
      - [x] Define an owned authorized-dispatcher port for the official SDK
        adapter and prove exact body and tenant transfer through it.
        - [x] Accept consuming zeroizing HTTP bodies so authorization and
          dispatch preserve one plaintext allocation without a borrowed-buffer
          clone.
        - [x] Model dispatch as an associated future so official asynchronous
          Tower services need no blocking bridge or macro dependency.
        - [x] Compose owned Axum authorization and asynchronous dispatch in one
          operation with typed authorization-versus-transport failures.
        - [x] Couple validated content negotiation and MCP protocol version
          with identity, invocation, and body through owned dispatch.
        - [x] Preserve the exact validated public host and browser origin in
          the consuming dispatch metadata for the official SDK boundary.
  - [x] Allow the shared MCP handler service to initialize canonical
    subject/client/workspace identity exclusively from verified remote claims.
  - [x] Bind remote sessions to issuer, resource, canonical identity,
    workspace, exact OAuth scope ceiling, and a non-extending expiry.
    - [x] Classify the exact `initialize` body before authentication and
      session allocation so malformed or substituted requests cannot reserve
      tenant-bound session capacity.
      - [x] Preserve one consuming zeroizing plaintext allocation through
        stateful initialization and every established-session POST dispatch.
      - [x] Roll back the new session binding when downstream SDK
        initialization fails, retaining capacity only after successful
        dispatch.
  - [x] Add a bounded session registry with URL-safe identifiers,
    duplicate/capacity controls, per-request revalidation, and authenticated
    deletion, reclaiming expired capacity before accepting new sessions.
    - [x] Separate termination authorization from deletion commit so an HTTP
      transport can retain the local binding until downstream confirmation.
  - [ ] Serve Streamable HTTP through the official Rust MCP SDK.
    - [ ] Wire the implemented provider-construction, tool, and OAuth worker
      boundaries into the actual SDK listener and verify end-to-end overload,
      cancellation, and real-provider behavior.
    - [x] Pin the reviewed official Rust MCP SDK release exactly so the
      transport API and dependency resolution cannot drift before remote
      transport enablement.
    - [x] Make production readiness fail closed until the official SDK server
      feature, remote authorization adapter, and concrete Streamable HTTP
      service are all wired into the MCP application.
      - [x] Derive pinned SDK features and adapter dependencies from offline
        Cargo metadata and reject comment-only service-instantiation markers.
      - [x] Require the detected official SDK service to compile from the
        committed lockfile in offline mode before production readiness passes.
    - [x] Authorize protocol-correct sessionless initialize requests without
      reserving a client-supplied ID before the official SDK response.
      - [x] Bound concurrent downstream initialization with anonymous,
        move-only capacity reservations that never trust a client-supplied
        session identifier.
        - [x] Hold each shared initialization reservation across SDK dispatch
          with cancellation-safe cleanup, release it on transport failure, and
          reject exhausted capacity before invoking the downstream service.
      - [x] Commit only the official SDK response session ID against the exact
        verified tenant with bounded duplicate and capacity enforcement.
        - [x] Compensate a capacity-rejected local session commit by
          terminating the downstream SDK session, while treating duplicate
          IDs as collisions that must not delete a pre-existing session.
          - [x] Preserve any attempted compensation failure for fail-closed
            operational handling.
        - [x] Expose confirmed initialization through borrowed and owned Axum
          boundaries while preserving one zeroizing request-body allocation.
          - [x] Provide shared concurrent Axum authorization that releases the
            bounded session-registry lock before every SDK initialization or
            compensating termination await.
            - [x] Perform bearer verification and operation-scope
              authorization before acquiring the session-registry lock,
              including potentially remote token introspection.
            - [x] Apply the same two-phase locking to established-session POST
              and confirmed DELETE, denying requests after committed deletion.
            - [x] Release the shared gate lock before stateless POST and
              event-stream GET dispatch so every supported HTTP route permits
              concurrent downstream execution.
        - [x] Validate successful Tower SDK responses with exactly one
          canonical session ID and reuse the validated host, origin, and
          protocol metadata for compensating DELETE requests.
        - [x] Route confirmed initialization and compensation through the
          exact tenant-aware service factory/cache, proving distinct generated
          sessions remain isolated across two workspaces.
          - [x] Prove local commit rejection reuses the same cached tenant
            service for downstream compensation without reconstruction or
            cross-tenant selection.
    - [x] Require every remote tool invocation to carry the exact verified
      subject, client, and workspace identity through the SDK request context,
      rejecting missing or substituted tenant extensions.
    - [x] Select or construct the Tower MCP service only after OAuth
      authorization using the exact verified tenant, without forwarding the
      bearer credential into the protocol service.
      - [x] Prove per-tenant service selection for authorized POST,
        stateless event-stream GET, and confirmed session DELETE dispatch.
      - [x] Fail closed before protocol dispatch when tenant-specific service
        construction is unavailable.
      - [x] Move tenant service selection/construction off executor threads
        for POST, SDK initialization/compensation, GET, and DELETE through a
        process-shared eight-job factory budget separate from OAuth/tool work.
        - [x] Return a redacted factory-unavailable failure before construction
          or SDK work when capacity is exhausted/closed or a worker panics.
        - [x] Hold factory capacity until real completion after abandonment
          and retain completed cached initialization without duplicate builds.
        - [x] Prove blocking-client construction, exact verified identity,
          all-route overload denial, panic cleanup, and cancellation ownership.
      - [x] Cache tenant-pinned Tower services by exact issuer, resource,
        principal, client, workspace, and OAuth scope set so refreshed tokens
        preserve SDK sessions without cross-tenant reuse.
        - [x] Bound cached tenant services without eviction, failing closed
          rather than silently discarding live protocol session state.
        - [x] Serialize concurrent first construction per tenant and leave
          capacity reusable after a failed service build.
          - [x] Reserve ready-plus-pending capacity atomically, release the
            global cache lock before construction, and wait only for the same
            exact tenant identity without blocking unrelated cache lookups.
          - [x] Release pending reservations and wake waiters after errors or
            constructor panic without poisoning the shared cache mutex.
          - [x] Prove unrelated ready/cold tenants continue during a slow
            constructor, pending slots count toward capacity, and concurrent
            refresh reuses one service while retaining the latest expiry.
        - [x] Track the latest validated token expiry per exact tenant service
          and reclaim only entries whose authorization lifetime has ended.
          - [x] Destroy retired services outside the global cache lock; prove
            unrelated tenant progress and reclaimed capacity during blocked
            cleanup, panic recovery, and preservation of pending reservations.
    - [x] Add a consuming Tower dispatcher that reconstructs only validated
      MCP protocol headers, strips the bearer credential at the OAuth boundary,
      and injects verified tenant access into request extensions for the
      official SDK service.
      - [x] Route authorized stateless event-stream GETs through the same
        dispatcher with an empty body and verified tenant-only extensions.
      - [x] Transfer POST request bytes into the Tower body without copying
        them out of zeroizing ownership.
      - [x] Dispatch authenticated session DELETE through Tower before
        committing the local tenant-bound session removal, retaining the
        binding when downstream termination fails.
        - [x] Parse and reject ambiguous Axum DELETE security and protocol
          headers before entering the confirmed termination flow.
  - [x] Add OAuth and cross-tenant transport integration tests.
    - [x] Prove verified remote identity is still constrained by canonical
      workspace membership, audience, expiry, and token validity.
      - [x] Route real RFC 7662 verifier output through the Axum authorization
        and consuming dispatch boundary for two isolated workspaces.
    - [x] Prove the Axum boundary preserves distinct verified workspace
      identities and rejects an untrusted browser origin over HTTP routing.
      - [x] Route both tenants through the owned asynchronous dispatcher and
        prove dispatched workspace identity remains isolated per request.
        - [x] Route concurrent stateless event-stream GETs through Axum and
          prove distinct OAuth tenants remain isolated before stream opening.
  - [x] Add a hardened Cloudflare Tunnel Compose overlay that keeps persistent
    memory and encryption credentials on the operator-controlled origin.
    - [x] Mount the remotely managed tunnel token as an owner-only file instead
      of exposing it through rendered process arguments.
- [x] Persist a disclosure receipt for every SQLite context response.
  - [x] Redact memory, checkpoint, travel, and graph disclosure routing,
    purpose, resource, and timeline details from diagnostics.
  - [x] Redact query plaintext, purpose, scopes, tenant and principal routing,
    client grants, context-pack IDs, and disclosure IDs from application
    context-resolution command diagnostics.
  - [x] Redact plaintext, identities, providers, source references, and
    timelines from application travel-context command and response diagnostics.
- [x] Require every future context storage adapter to implement disclosure
  persistence through compile-time composite repository capabilities.
- [x] Prove cross-tenant denial across SQLite user-facing read paths.
- [x] Require workspace identity for internal projection-job lookups.
- [ ] Prove cross-tenant denial across every future adapter read path.
  - [x] Cover every currently implemented PostgreSQL tenant-facade point and
    collection read with a mismatched workspace before pool access.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.
  - [x] Remove destructive fixture resets; require explicit disposable-database
    authorization, private libpq service configuration, and a read-only empty
    target/role check before migrations, with executable fail-closed guard tests.
  - [ ] Execute the hardened fixture runner against live PostgreSQL in CI/staging;
    fake-client guard tests do not prove SQL execution or RLS behavior.
  - [x] Replace source-regex runtime readiness with resolved Cargo dependency
    checks, compilation of an enabled integration target, and a separate live
    five-test matrix that rejects filtered/ignored/failed execution and redacts
    diagnostics. Verify gate refusal/admission with fake-Cargo regression tests.
  - [ ] Implement and execute that concrete-driver live integration matrix;
    checker fixtures do not establish pool/repository behavior.
  - [x] Add deny-by-default forced RLS policy generation for every canonical
    `workspace_id` table plus explicit workspace and share-proposal policies.
  - [x] Add the canonical encrypted PostgreSQL base schema and isolate
    principal reads through the current workspace's visible memberships.
  - [x] Add PostgreSQL shared-workspace administration, key-rotation,
    retention, legal-hold, and append-only audit schemas under forced RLS.
  - [x] Add encrypted PostgreSQL trip, booking-research, checkpoint
    disclosure, and sensitive travel-disclosure schemas under forced RLS.
  - [x] Add encrypted temporal knowledge-graph and idempotent graph-projection
    PostgreSQL schemas under forced RLS.
  - [x] Add PostgreSQL channel replay, active-member bindings, encrypted inbox
    leasing, retry/quarantine, and channel-administration audit schemas.
  - [x] Enforce complete canonical table-inventory parity between SQLite and
    PostgreSQL migrations in the static security gate.
  - [x] Document transaction-local tenant identity and non-owner,
    non-`BYPASSRLS` runtime-role requirements.
    - [x] Verify restricted runtime authority before tenant setup and each
      repository read/write, with opaque denial and rollback on proof failure
      or role drift.
    - [x] Share the exact runtime guard SQL with live PostgreSQL role,
      ownership, forced-RLS, view, and search-path-shadowing fixtures.
    - [ ] Execute the new runtime-authority SQL fixtures against PostgreSQL;
      local driver-boundary unit tests do not substitute for this proof.
    - [x] Require prepared `set_config(..., $1, true)` tenant bootstrap,
      exact context read-back, and pooled-connection leakage coverage.
  - [x] Run a live PostgreSQL two-tenant CI proof covering scoped reads,
    denied cross-tenant writes, and fail-closed missing tenant context.
  - [ ] Implement the Rust PostgreSQL repository adapter and live two-tenant
    integration suite.
    - [x] Make production readiness fail closed when only the schema/RLS proof
      exists without a concrete Rust database driver and public runtime
      pool-or-repository implementation.
    - [x] Add a driver-neutral owned transaction boundary that parameterizes
      tenant bootstrap, requires exact canonical read-back, and rolls back
      missing, mismatched, failed, or uncommitted tenant transactions.
      - [x] Revalidate tenant state before every repository operation and
        permanently close a transaction after detected context drift.
      - [x] Add a driver-neutral pool boundary that begins and verifies a fresh
        transaction for every tenant operation and sequential pool reuse.
      - [x] Implement the first typed repository read for exact workspace
        lookup with closed row decoding and cardinality enforcement.
      - [x] Add exact tenant-and-principal membership lookup with closed role
        and lifecycle-status decoding for authorization decisions.
      - [x] Add deterministic bounded active-member enumeration with duplicate
        principal rejection for authorization and key-rotation recipients.
      - [x] Maintain an executable cross-workspace denial matrix across all
        implemented administrative, canonical-memory, travel, checkpoint,
        graph, event, and projection reads.
      - [x] Classify foreign-workspace disclosure writes as access denial
        before transaction acquisition rather than input validation.
      - [x] Authorize foreign-workspace canonical, checkpoint, travel, event,
        and graph mutations before structural validation, optimistic
        concurrency checks, encryption, or pooled transaction acquisition.
        - [x] Authorize every graph projection job in a canonical node or edge
          batch before version checks, lineage reads, encryption, or pool
          access.
      - [x] Reject foreign-workspace administrative audit evidence across
        tenant-bound invitation creation, acceptance, and revocation before
        transaction acquisition.
      - [x] Add tenant-visible principal lookup with exact identity
        correlation under the membership-mediated RLS policy.
      - [x] Add tenant-verified membership insert and lifecycle replacement
        with exact affected-row and commit enforcement.
      - [x] Implement the complete application `MembershipRepository` port
        with driver-neutral SQLSTATE classification and opaque error mapping.
      - [x] Implement tenant-pinned administrative audit append and bounded
        chronological reads with closed action/target decoding.
      - [x] Add exact tenant-scoped retention-policy lookup with bounded
        cardinality and closed finite/forever period decoding.
        - [x] Add atomic audited policy insertion and optimistic replacement
          with strict successor validation and nullable forever periods.
      - [x] Add exact and bounded active legal-hold reads with lifecycle
        restoration, tenant correlation, and duplicate rejection.
        - [x] Add atomic audited legal-hold placement and optimistic release,
          completing the PostgreSQL `RetentionRepository` port.
        - [x] Redact workspace, administrator, hold, request, and retention
          timeline identities from application policy, legal-hold, and purge
          diagnostics.
      - [x] Implement tenant-pinned member-scope grant insertion, bounded
        listing with closed scope decoding, and audited exact deletion.
      - [x] Add tenant-verified latest key-rotation and provider-receipt reads
        with strict row correlation and bounded recipient reconstruction.
        - [x] Complete the tenant-pinned `KeyRotationRepository` with atomic
          optimistic completion, receipt/recipient writes, and audit evidence.
      - [x] Atomically remove members, revoke all stored scopes, serialize the
        next required key generation, and persist both lifecycle audit events.
        - [x] Redact workspace, member, administrator, scope-resource, request,
          rotation, provider, and key identities from membership administration
          diagnostics.
      - [x] Compose PostgreSQL membership, scope, and key-rotation ports through
        client authorization, including fail-closed pending-rotation denial.
        - [x] Redact client, workspace, principal, scope, and effective-grant
          identities from authorization command and result diagnostics.
      - [x] Add a tenant-and-cipher PostgreSQL memory facade for exact and
        bounded subject reads with authenticated domain-record correlation.
        - [x] Prove memory, event, checkpoint, travel, knowledge-graph, and
          graph-outbox reads reject cross-workspace identifiers before pool
          access.
        - [x] Add optimistic encrypted canonical-event append and bounded
          authenticated event-stream reads through the same tenant facade.
        - [x] Atomically insert or revise encrypted memories with evidence,
          canonical events, optimistic versions, and provider projection jobs.
      - [x] Add a tenant-pinned PostgreSQL provider projection outbox with
        bounded pending reads and optimistic lifecycle transitions.
        - [x] Compose encrypted memory reads and projection outbox operations
          on one tenant facade suitable for the provider projection worker.
        - [x] Run the real projection worker through PostgreSQL into the native
          semantic provider and complete the durable outbox lifecycle.
      - [x] Persist tenant-scoped disclosure receipts with exact subject and
        memory-version verification before context crosses a trust boundary.
        - [x] Run application context resolution end to end over PostgreSQL and
          prove every returned memory revision is disclosure-audited.
      - [x] Add authenticated PostgreSQL latest-checkpoint and bounded
        subject-history reads for development working memory.
        - [x] Atomically insert and revise encrypted PostgreSQL checkpoints
          with optimistic versions and canonical event-stream sequencing.
        - [x] Persist an exact-version PostgreSQL disclosure receipt whenever
          a checkpoint revision is handed to an external client.
          - [x] Run the application checkpoint-resume service end to end over
            PostgreSQL and require disclosure commit before returning state.
      - [x] Add authenticated PostgreSQL exact-trip and bounded owner-history
        reads for cross-assistant travel continuity.
        - [x] Atomically insert and revise encrypted PostgreSQL trips with
          strict versions, owner correlation, and canonical event sequencing.
        - [x] Redact itinerary, traveler, constraint, decision, provenance,
          tenant, and event details from application trip-mutation diagnostics.
        - [x] Add authenticated PostgreSQL exact and bounded per-trip booking
          research reads with researcher and version correlation.
          - [x] Atomically capture encrypted PostgreSQL booking research with
            a researcher-bound canonical event and optimistic stream sequence.
          - [x] Redact provider, itinerary, source-reference, provenance,
            tenant, trip, and actor details from application command
            diagnostics.
          - [x] Persist exact-version PostgreSQL travel disclosures with
            verified trip/research revisions and sensitivity flags.
            - [x] Run travel-context resolution end to end over PostgreSQL,
              preserving trip ownership while auditing an authorized reader.
      - [x] Add authenticated PostgreSQL knowledge-node, edge, and bounded
        temporal neighbourhood reads for graph-aware context retrieval.
        - [x] Add encrypted PostgreSQL node and edge creation/revision with
          strict versions and endpoint/relation lineage validation.
        - [x] Add a tenant-pinned PostgreSQL graph projection outbox lifecycle
          for pluggable native and Graphiti indexers.
          - [x] Commit encrypted PostgreSQL graph revisions and their validated
            provider projection jobs in one tenant transaction.
          - [x] Run the graph projection worker through the PostgreSQL facade
            into the native graph provider and complete the durable lifecycle.
      - [x] Add exact invitation lookup and bounded status-filtered listing
        with terminal-state restoration and full tenant/identifier correlation.
      - [x] Implement atomic invitation creation, acceptance, revocation,
        membership activation, and content-free administrative audit writes.
        - [x] Redact invitation, workspace, invitee, actor, request, and
          timeline identities from application command diagnostics.
        - [x] Move invited-principal existence enforcement into each storage
          boundary so tenant services never require a global principal read.
      - [x] Add an application-facing tenant store that pins membership and
        invitation ports to one workspace before any pool access.
        - [x] Split tenant-safe workspace lookup from privileged workspace
          provisioning and run invitation services on the runtime-only facade.
      - [x] Separate privileged first-workspace provisioning into an explicit
        rollback-on-drop pool boundary that runtime request paths cannot use
        accidentally.
        - [x] Atomically provision personal identities and shared workspaces
          with correlated active owner memberships and exact write counts.
        - [x] Implement the full workspace administration port through a
          target-bound control-plane store with privileged principal lookup.
    - [x] Define a reference-only PostgreSQL connection profile with explicit
      transport security and bounded pool capacity.
      - [x] Prevent derived debug logging of the database secret locator.
      - [x] Redact concrete driver diagnostics from PostgreSQL store and
        tenant-transaction display and debug output.
      - [x] Redact text and byte content from PostgreSQL parameter diagnostics
        before a concrete driver can log the adapter boundary.
        - [x] Statically reject derived debug output on production PostgreSQL
          adapter structs to preserve reviewed diagnostic boundaries.
      - [x] Resolve and validate the PostgreSQL URL through any deployment
        secret resolver into non-cloneable zeroizing adapter configuration.
        - [x] Reject missing, duplicate, or contradictory `sslmode` values
          before the database driver opens a connection.

## Phase 2 — Development continuity

- [x] Canonical temporal knowledge graph.
  - [x] Define engine-neutral, typed workspace-scoped nodes and relationships
    with separate event/system time, validity windows, provenance, bounded
    aliases, and explicit supersession references.
    - [x] Redact graph semantics, labels, aliases, timelines, provenance,
      endpoints, supersession identities, and tenant identities from
      diagnostics.
  - [x] Add tenant-isolated mutation and neighbourhood repository contracts
    with bounded temporal traversal and optimistic version checks.
  - [x] Re-authorize untrusted graph-provider candidates against exact
    canonical workspace, edge version, endpoint direction, and validity time
    before exposing graph context.
    - [x] Require the graph-context command's verified read grant to match the
      requested workspace before invoking any provider or repository.
    - [x] Require append-only disclosure evidence containing the exact
      canonical edge revisions, query direction, validity time, client,
      subject, and purpose before returning graph context.
      - [x] Deny graph retrieval before provider access when the requested
        domain/entity scope is absent or the disclosure purpose is empty.
    - [x] Expose graph context through authenticated interoperable protocol
      surfaces.
      - [x] Reserve a dedicated `rembrane:graph:read` OAuth scope and
        fail-closed remote MCP operation classification.
        - [x] Prove remote graph dispatch rejects missing OAuth graph scope and
          preserves distinct verified workspace identity across tenants.
      - [x] Define one transport-neutral graph-context request and response
        carrying explicit scope, temporal direction, bounds, purpose, exact
        canonical edges, and disclosure identity.
      - [x] Bind transport principal identity to the verified grant before
        converting the neutral request into a provider traversal.
      - [x] Add a local/remote MCP graph-context tool backed by the
        deployment-selected native or Graphiti provider and canonical SQLite
        reauthorization.
        - [x] Prove executable stdio MCP scope denial and disclosure
          persistence for an empty native-provider neighbourhood.
      - [x] Add an authenticated REST graph-context endpoint sharing the same
        configured provider, canonical reauthorization, and disclosure path.
        - [x] Add exact-route graph-context operations to the TypeScript and
          Python SDKs.
        - [x] Add exact-route graph-context operations to the Swift and Kotlin
          SDKs with executable transport smoke coverage.
        - [x] Prove black-box REST scope denial and disclosure persistence for
          an empty native-provider neighbourhood.
          - [x] Add the executable acceptance scenario; run it in unrestricted
            CI where loopback listener creation is permitted.
          - [x] Add portable Postman assertions for denied scope, canonical
            empty output, and a distinct persisted disclosure receipt.
          - [x] Lock the graph OpenAPI bindings and both Postman acceptance
            cases into the unconditional protocol compatibility gate.
      - [x] Deny implicit global REST context requests when the connection has
        only narrower domain, entity, or activity grants.
    - [x] Persist graph disclosure evidence in the in-memory, SQLite, and
      PostgreSQL repository adapters with tenant-isolation coverage.
      - [x] Enforce exact tenant and edge-revision correlation in the
        in-memory reference adapter.
      - [x] Persist tenant-scoped graph disclosure receipts and exact disclosed
        edge revisions atomically in SQLite.
      - [x] Implement the tenant-pinned PostgreSQL graph disclosure port with
        bounded duplicate rejection and exact canonical revision checks.
      - [x] Include SQLite graph disclosure headers and cascaded edge evidence
        in bounded disclosure-retention purges.
  - [x] Add local SQLite graph persistence and Graphiti projection adapter.
    - [x] Construct Graphiti from validated provider profiles through any
      deployment-selected secret resolver without fixed credential names.
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
      - [x] Redact Graphiti mapping content, resource identities, timelines,
        and deletion targets and enforce the invariant statically.
      - [x] Define a versioned, bounded sidecar protocol with workspace-derived
        namespaces, mutation idempotency, and response correlation.
      - [x] Implement the transport-injected Graphiti graph provider.
      - [x] Add authenticated bounded HTTP transport with strict origin,
        credential, timeout, redirect, response-size, manifest, and response
        correlation validation.
        - [x] Transfer serialized graph mutations and queries to HTTP through
          zeroizing request-body ownership.
        - [x] Zeroize bounded raw Graphiti response bodies after typed
          decoding.
        - [x] Reject neighbour collections above the exact candidate count
          negotiated by each canonical request.
        - [x] Bound manifest capability collections to Graphiti's finite
          protocol surface before capability conversion.
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
          - [x] Resolve the environment-selected Graphiti bearer credential
            from validated environment or protected-file reference metadata.
          - [x] Align Graphiti runtime, privacy diagnostics, documentation, and
            canonical environment variables on one protected provider profile.
          - [x] Resolve the Graphiti sidecar bearer credential through the
            same protected local locator grammar and mount one mode-restricted
            Compose secret into both worker and sidecar.
          - [x] Fail closed when the Graphiti request-correlation sequence is
            exhausted instead of wrapping and reusing request identifiers.
          - [x] Keep Graphiti Neo4j and model-provider credentials out of
            Compose environment interpolation using protected file references
            and official Neo4j auth-file injection.
          - [x] Reuse the container secret-staging boundary in the Graphiti
            sidecar before dropping to its dedicated numeric service user.
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
- [x] Expose activity work-trace capture through the local CLI without
  promoting agent observations to confirmed user truth.
- [x] Model activity checkpoints and resumable handoffs.
  - [x] Redact checkpoint identities, working-memory plaintext, and external
    state fingerprints from diagnostics while retaining safe structural
    metadata.
- [x] Expose encrypted checkpoint create, optimistic update, and audited resume
  operations through the local CLI.
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
- [x] Executable CLI/MCP preference and project-checkpoint handoff proof using
  independent clients over one encrypted workspace store.
- [x] Prove REST-to-CLI project continuation after the API process stops,
  including exact checkpoint version, state freshness, and disclosure audit.

## Phase 3 — Travel continuity

- [x] Expose the complete implemented REST travel lifecycle through the
  TypeScript and Python SDKs.
- [x] Publish protocol-accurate TypeScript travel enums and response models
  instead of generic caller-selected return types.
- [x] Reject malformed travel workspace, subject, trip, and participant
  identifiers in the TypeScript SDK before network access.
- [x] Publish dependency-free Python `TypedDict` travel request and response
  contracts with closed protocol literals.
- [x] Reject malformed travel workspace, subject, trip, and participant
  identifiers in the Python SDK before network access.
- [x] Reject malformed or oversized opaque trip and participant references at
  the REST boundary before authorization or storage access.
- [x] Reuse layered domain/entity context for travel and trip constraints.
- [x] Trip entities, participants, constraints, and decisions.
  - [x] Canonical versioned trip aggregate with opaque participants, validated
    date windows, evidence-backed constraints, and attributed decisions.
  - [x] Versioned canonical trip wire format with strict aggregate
    reconstruction.
  - [x] Redact itineraries, dates, participant details, constraints, decisions,
    evidence, and identities from aggregate and nested travel diagnostics.
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
  - [x] Redact booking-research content, travel identities, provider and source
    details, evidence, and timelines from diagnostics.
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
  - [x] Redact invitation and cross-workspace sharing routes, exact scope
    selectors, and collaboration timelines from diagnostics.
  - [x] Bound invitation lifetime to 30 days and reject acceptance at or after
    expiry without creating membership.
    - [x] Atomically transition an expired pending invitation before creating
      a replacement so stale rows cannot block reinvitation.
  - [x] Commit content-free invitation creation, acceptance, and revocation
    audit evidence in the same transaction as each lifecycle mutation.
  - [x] Add bounded, status-filtered, deterministic invitation listing with
    owner/admin authorization across in-memory and SQLite repositories.
    - [x] Expose bounded invitation listing through the local CLI with closed
      status filters and structured JSON output.
    - [x] Expose bounded invitation listing through the authenticated REST API
      and portable OpenAPI contract.
    - [x] Add exact-route invitation listing operations to the TypeScript,
      Python, Swift, and Kotlin SDKs.
    - [x] Exercise filtered, bounded, tenant-scoped invitation listing through
      the Postman and shell REST acceptance flows.
  - [x] Expose shared-workspace creation plus invitation create, accept, and
    revoke workflows through the local CLI.
  - [x] Expose invitation creation, acceptance, and revocation through the
    authenticated REST API with a zero-authority pre-membership connection.
    - [x] Exercise owner-created and owner-revoked invitations through the
      executable Postman REST acceptance collection, then prove a
      zero-authority invited connection accepts into atomic active membership
      with persisted audit state.
  - [x] Expose the authenticated invitation lifecycle through the portable
    TypeScript, Python, Swift, and Kotlin SDKs with exact-route executable
    fixtures.
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
      - [x] Reject rotation receipts above the canonical 10,000-recipient
        ceiling before constructing provider-controlled principal identities.
    - [x] Orchestrate provider rotation and completion through the management
      API and CLI.
      - [x] Add authorization-first application orchestration and a configured
        provider CLI command.
      - [x] Add the authenticated management REST operation.
      - [x] Prove unauthorized callers cannot trigger provider side effects
        and removed members are excluded from the provider recipient set.
- [x] Organizational audit and retention controls.
  - [x] Redact workspace, principal, membership, grant, and exact scope
    identities from authorization diagnostics.
  - [x] Redact exact retention schedules, legal-hold routing identities,
    actors, and timestamps from diagnostics.
  - [x] Define an immutable bounded content-free administrative audit event
    contract with tenant, actor, closed action, opaque target, request
    correlation, and occurrence time.
    - [x] Redact administrative audit routing identities and occurrence times
      from diagnostics while retaining closed action and target kinds.
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
  - [x] Verify signed provider registries over exact no-follow registry,
    signature, and Ed25519 public-key reads.
  - [x] Produce registry signature bundles in new owner-only directories,
    rejecting unsafe keys and cleaning partial output on failure.
    - [x] Share the no-follow, owner-mode-enforcing Ed25519 signer with
      independent-review artifacts.
    - [x] Reject private-key material wherever a public verification trust
      anchor is required.
  - [x] Verify the exact three-file registry bundle, checksum, Ed25519
    signature, and provider conformance semantics in one process.
    - [x] Self-verify each newly signed bundle before publishing its path and
      reject correctly signed registries with invalid semantics.
    - [x] Publish the exact bundle separately from its independently trusted
      public key and verify the bundle before release upload.
- [x] Canonically parse and bound bring-your-own provider endpoints, allowing
  plaintext loopback only inside a declared trusted boundary.
- [x] Enforce provider protocol and declared limits at projection and retrieval
  boundaries.
- [x] Versioned HTTP sidecar contract for external semantic providers.
- [x] Secret-safe black-box HTTP sidecar conformance runner.
  - [x] Reject context and grounded-answer collections above each originating
    request's negotiated item ceiling before canonical item conversion.
  - [x] Reject oversized pull pages and non-exact push acknowledgement
    collections before converting provider-controlled synchronization items.
  - [x] Bound discovery transport, capability, and operation collections to
    the finite protocol surface before manifest conversion.
- [ ] Stable Memory Provider Protocol.
  - [ ] Satisfy the explicit `1.0` release gates in
    `spec/MEMORY_PROVIDER_STABILITY.md`.
    - [ ] Record pinned passing core-conformance evidence for at least two
      independent implementations, including one maintained outside this
      repository.
      - [x] Define and tamper-test the exact two-provider release evidence set,
        including external provenance and distinct maintainer enforcement.
      - [x] Provide a bounded dependency-light Node conformance runner for
        external providers and CI environments without curl or jq.
        - [x] Resolve its three workspace credentials through protected
          `env:` or `file:` references with opaque fail-closed errors.
          - [x] Exercise protected-file references in the socket-enabled
            independent mock-provider CI proof.
      - [x] Require the completed two-provider evidence set in strict
        production readiness.
    - [ ] Complete independent security review and resolve or explicitly
      accept every finding.
      - [x] Require an approving signed disposition in strict production
        readiness while retaining verification support for changes-required
        review bundles.
      - [x] Require accepted-risk approvals to identify their retained review
        record and contain an actual finding or explicit exclusion.
      - [x] Read review manifests, attestations, and tracked inventory through
        no-follow descriptors before hashing or parsing them.
        - [x] Verify Ed25519 signatures over the exact opened review bytes
          without handing their paths back to OpenSSL.
        - [x] Verify complete signed review bundles from one immutable opened
          artifact set without cross-process path reopening.
        - [x] Self-verify newly signed review artifacts and remove partial
          output when final correlation or signature checks fail.
        - [x] Load owner-only Ed25519 signing keys through no-follow
          descriptors and zero their input buffers after key construction.
        - [x] Generate checksums and verify manifest-attestation correlation
          through the same bounded byte-oriented modules.
    - [x] Publish compatibility, deprecation, and mixed-version negotiation
      policy.
      - [x] Include the normative compatibility policy in the tamper-tested
        protocol review lock.
    - [ ] Record mixed-version release-candidate evidence for the oldest and
      newest supported minor versions.
      - [x] Define and tamper-test a hash-bound evidence format covering both
        supported-minor directions and unsupported-major rejection.
    - [ ] Freeze the complete `1.0` artifact inventory and publish final
      migration notes from `0.1`.
      - [x] Review-lock the evidence formats and a fail-closed draft migration
        contract before the release candidate.
      - [x] Bind the exact candidate compatibility lock and migration notes
        into the two-provider release evidence set.
      - [x] Require provider and independent-review evidence to match the same
        clean release revision in strict production readiness.
      - [x] Expose production readiness as versioned, schema-validated
        machine-readable JSON so installers, CI, bots, and hosted control
        planes can report every unavailable release gate without parsing
        human diagnostics.
        - [x] Fail static verification when emitted gate labels exceed schema
          bounds, collide, contain non-printable bytes, or drift from the
          declared readiness schema version.
        - [x] Enforce the same label size, count, uniqueness, and printable-byte
          invariants while constructing runtime readiness results.
      - [x] Package exact two-provider release evidence through a
        non-overwriting, symlink-rejecting, self-verifying local tool.
      - [x] Replace self-asserted external provenance with a detached provider
        result signature under an operator-selected Ed25519 trust anchor.
        - [x] Define and tamper-test a signed provenance statement binding the
          external maintainer, source revision, result digest, and signing time.
        - [x] Generate canonical provenance deterministically from bounded
          result bytes before external signing.
          - [x] Document and test external signing through the shared
            no-follow Ed25519 tool instead of direct OpenSSL path access.
        - [x] Read untrusted release artifacts through no-follow file
          descriptors and verify signatures over the already-opened bytes.
  - [x] Add a machine-verifiable compatibility lock over the canonical wire
    schemas, HTTP binding, conformance profile, and lifecycle fixtures so
    protocol changes require explicit review.
    - [x] Tamper-test the compatibility verifier against an independently
      copied canonical schema in the unconditional static gate.
      - [x] Reject compatibility locks that omit any reviewed artifact.
      - [x] Reject semantically rebound conformance evidence even when its
        attacker-modified hash is present in the lock.
      - [x] Reject reordered conformance cases even when the modified result
        digest is present in the lock.
    - [x] Bind profile, lifecycle fixture, result schema, and example evidence
      to exact reviewed profile and fixture identifiers.
      - [x] Require result case identity and order to match the reviewed
        profile exactly.
      - [x] Bind portable evidence to SHA-256 digests of the exact reviewed
        profile and lifecycle fixture bytes.
        - [x] Reject evidence after profile bytes change even when the
          modified profile is rehashed into the compatibility lock.
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
  - [x] Validate the complete closed provider discovery manifest, canonical
    operation bindings, limits, privacy mode, and capability parity before
    running third-party conformance operations.
  - [x] Validate public third-party discovery before resolving any conformance
    bearer credential reference.
  - [x] Restrict both conformance clients to credential-free origin URLs using
    HTTPS or literal loopback HTTP, rejecting paths and `localhost`.
  - [x] Enforce the complete closed discovery manifest and canonical operation
    registry in the portable jq/shell conformance client.
  - [x] Harden shell conformance HTTP with direct connections, strict timeout
    and response-size ceilings, JSON media checks, and exact correlation
    header validation.
  - [x] Validate shell-provider discovery before validating or materializing
    bearer credentials into owner-only curl header files.
  - [x] Bind both conformance runners to the exact reviewed profile and fixture
    bytes so unexecuted custom cases cannot be reported as passing.
  - [x] Require exact closed error bodies for unauthenticated, insufficient
    scope, and optimistic-conflict conformance cases.
  - [x] Require closed canonical proposal and deletion success results before
    accepting provider-assigned identities or tombstone versions.
  - [x] Validate closed context results down to selectors, evidence,
    sensitivity, confidence, validity, and disclosure constraints.
  - [x] Validate closed sync pages, cursor and pagination invariants, change
    variants, resources, payload limits, and Node-side payload SHA-256 binding.
  - [x] Verify actual upsert payload SHA-256 values in the portable shell
    conformance path without exposing decoded payloads.
    - [x] Add bounded context-resolution requests with global, domain, entity,
      and activity selectors constrained by provider-advertised limits.
      - [x] Seal selector representation so callers cannot bypass domain and
        opaque-ID validation through direct enum construction.
      - [x] Redact provider question prompts, answers, supporting memory
        revisions, and receipt identities from diagnostics.
    - [x] Add bounded context responses carrying canonical IDs, versions,
      scopes, kinds, evidence, confidence, validity, sensitivity, disclosure
      constraints, and disclosure receipts.
      - [x] Redact provider context queries, purposes, memory plaintext,
        provenance identities, validity times, expiry times, and disclosure
        identities from diagnostics.
    - [x] Add idempotent memory-proposal payloads that preserve validated
      scope, memory kind, provenance source, and observation time without
      allowing clients to assert confirmed status.
      - [x] Redact proposal plaintext, provenance references, observation
        times, idempotency keys, and result identities from provider
        diagnostics.
    - [x] Add bounded idempotent activity-checkpoint create/update payloads
      with explicit optimistic versions and canonical checkpoint identities.
      - [x] Redact provider checkpoint working memory, state fingerprints,
        idempotency keys, and canonical identities from diagnostics.
    - [x] Add append-only disclosure receipt payloads containing exact memory
      revisions while deriving workspace, subject, and client identity solely
      from authenticated connection context.
      - [x] Redact provider disclosure purposes, timestamps, idempotency keys,
        memory revisions, context packs, and receipt identities from
        diagnostics.
    - [x] Add exact-version idempotent deletion and bounded provenance
      explanation payloads without caller-controlled authorization identity.
      - [x] Redact provider deletion reasons, explanation purposes and text,
        idempotency keys, evidence identities, and memory identities from
        diagnostics.
    - [x] Add idempotent bounded event-batch payloads with exact scope,
      provenance references, observation time, and canonical ordered results.
      - [x] Redact provider work traces, event types, provenance references,
        observation times, idempotency keys, and canonical identities from
        diagnostics.
    - [x] Add bounded scoped question payloads and answers grounded in exact
      memory revisions with context-pack and disclosure receipt identity.
    - [x] Add cursor-bound bounded sync pull/push payloads with server-assigned
      ordering, optimistic atomic mutations, ciphertext-compatible content
      digests, and no caller-controlled tenant identity.
      - [x] Redact provider sync cursors, payloads, digests, idempotency keys,
        and resource, change, and mutation identities from diagnostics.
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
    - [x] Resolve environment-selected HTTP bearer credentials from protected
      local environment or file references while preserving the legacy
      environment-variable default and zeroizing ownership.
    - [x] Consume validated Mem0 or Supermemory profiles through any
      deployment-selected secret resolver.
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
    - [x] Transfer serialized portable memory operations through zeroizing
      request-body ownership.
    - [x] Zeroize bounded raw portable-provider responses after typed
      operation decoding.
    - [x] Include discovery and policy negotiation, and let configured
      composition own any boxed client implementation.
- [x] Versioned key-provider sidecar protocol for OS, HSM, and customer-KMS
  adapters.
  - [x] Lock the reviewed OpenAPI, discovery fixture, conformance schema,
    result fixture, and black-box runner with tamper-tested SHA-256 evidence.
    - [x] Require the exact artifact set and one matching protocol version
      across OpenAPI, discovery, conformance schema, and result fixture.
    - [x] Reject semantically rebound result evidence even when an updated
      digest matches the attacker-modified artifact.
    - [x] Reject reordered result cases even when an updated digest matches
      the attacker-modified artifact.
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
      - [x] Preserve zeroizing ownership for serialized requests and wipe
        transient base64 plaintext around seal and open operations.
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
  - [x] Document secure TypeScript and Python client setup, portable
    export/import handling, plaintext risk, and optimistic import sequencing.
  - [x] Bound the published TypeScript package to runtime, declarations, and
    documentation, and include the Python SDK guide as package metadata.
  - [x] Publish the transport-neutral Rust provider SDK and authenticated HTTP
    implementation.
  - [x] Publish and compile-test a Swift Package with injectable async
    transport and a redirect-rejecting URLSession implementation.
    - [x] Add authenticated raw-byte portable exports and bounded atomic JSONL
      imports with strict metadata, opaque-ID, and response validation.
    - [x] Add named Kotlin preference, work-trace, correction, deletion,
      checkpoint, and resume operations with path-safe opaque identifiers.
    - [x] Add the complete Kotlin travel continuity route set for trips,
      participants, constraints, decisions, research, and context resolution.
    - [x] Document protected plaintext handling and sequence-safe imports for
      Swift adopters, and link all application SDK guides from the project root.
    - [x] Add named Swift preference, work-trace, correction, deletion,
      checkpoint, and resume operations with path-safe opaque identifiers.
    - [x] Add named Swift audited context resolution for API parity.
    - [x] Add unauthenticated Swift capability discovery with closed,
      bounded schema checks and exact configured API-root correlation.
    - [x] Add the complete Swift travel continuity route set for trips,
      participants, constraints, decisions, research, and context resolution.
    - [x] Add Swift workspace key-rotation and retention administration routes
      for policy, legal holds, and bounded purges.
  - [x] Publish a dependency-free Kotlin/JVM client package with injected
    transport and an executable smoke fixture.
    - [x] Add authenticated raw-byte portable exports and bounded atomic JSONL
      imports with strict metadata, opaque-ID, and response validation.
    - [x] Execute the Kotlin compiler smoke fixture in a pinned Ubuntu 24.04
      CI environment that fails if `kotlinc` or Java is unavailable.
- [x] Reusable semantic-provider conformance suite.
  - [x] Lock the exact reviewed wire contract, manifest, core profile,
    portable evidence, and black-box runner with tamper-tested SHA-256
    evidence.
  - [x] Return typed provider/build/namespace evidence from the Rust harness
    and emit strict six-case JSON evidence from every installed CLI adapter.
  - [x] Publish and statically verify the portable semantic-provider
    conformance result schema and example.
  - [x] Bind portable results and registry evidence to the SHA-256 of the
    exact reviewed semantic-provider core profile.
- [x] Evidence-backed provider compatibility registry schema and initial
  native-provider record.
  - [x] Persist exact suite, protocol, disposable namespace, and six-case
    evidence from a fresh native CLI conformance run.
    - [x] Require the provider build reported by conformance to match the
      registry adapter version exactly.
- [x] Expose the build-pinned compatibility registry through the CLI.
  - [x] Add a fail-closed provider eligibility command that pins the exact
    adapter build, requires experimental opt-in, and rejects deprecated,
    revoked, missing, or ambiguous records.
    - [x] Require exact passing profile-bound conformance evidence and a
      separate explicit opt-in before selecting any plaintext-processing
      provider.
    - [x] Emit a strict portable selection receipt binding approvals to the
      exact provider build, protocol, source revision, conformance profile,
      and test timestamp.
      - [x] Bind each selection receipt to the exact registry snapshot bytes
        and generation timestamp.
        - [x] Reject impossible, non-canonical, and future registry timestamps
          before issuing a selection receipt.
      - [x] Accept bounded external registry snapshots only with a valid
        detached Ed25519 signature under an explicitly supplied trust anchor.
        - [x] Record embedded versus external trust mode and the canonical
          Ed25519 public-key fingerprint in every selection receipt.
        - [x] Extract registry hashing, signature verification, and trust
          provenance into a reusable Rust crate for non-CLI integrations.
        - [x] Expose typed reusable provider-selection policy and receipt
          contracts with build, conformance, time, status, and privacy checks.
          - [x] Route CLI eligibility through the shared typed selection API
            and remove its duplicate policy engine.
          - [x] Reject unsupported registry schemas, malformed provider IDs,
            invalid or duplicate protocols, and invalid or duplicate
            deployment modes before issuing portable selection receipts.
          - [x] Allow integrations to pin the exact registry digest or a
            minimum trusted generation time to reject signed snapshot replay
            and rollback.
            - [x] Expose both snapshot constraints through the CLI for
              operator-managed and automated integration workflows.
- [x] Run installed native-provider conformance through the CLI.
- [x] Automated external-provider registry verification and release signing.
  - [x] Redact signed registry bytes, trust-anchor fingerprints, provider and
    adapter identities, evidence revisions, hashes, and timestamps from
    registry verification and selection diagnostics.
  - [x] Verify registry identity, timestamps, conformance status, and pinned
    native Git evidence in the repository static gate.
    - [x] Represent provider revocation as a signed, timestamped, closed-reason
      state that cannot be attached to an active registry entry.
    - [x] Tamper-test missing, reordered, protocol-mismatched, false-pass, and
      unsafe-namespace conformance evidence.
      - [x] Route standalone and signed-bundle verification through the same
        byte-oriented semantic validator.
  - [x] Produce and tamper-test detached Ed25519 signatures using an
    externally supplied private key.
  - [x] Publish signed registry artifacts from published GitHub releases using
    a repository-secret Ed25519 key and an ephemeral mode-restricted key file.
  - [x] Require a passing conformance result before any external provider can
    be promoted to compatible.
  - [ ] Add the first external provider only after its disposable-namespace
    conformance run produces reviewable evidence.
    - [x] Fail closed when Supermemory search or exact-deletion responses bind
      canonical memory metadata to a substituted provider document identity.
      - [x] Authenticate Supermemory workspace, memory, and version metadata
        so a valid document pseudonym cannot carry a forged revision.
    - [x] Authenticate Mem0 workspace, memory, and version metadata with a
      deployment-keyed binding before retrieval or lifecycle mutations.
- [x] WhatsApp Business gateway.
  - [x] Verify webhook HMAC-SHA256 over the raw bounded payload before parsing
    and derive keyed pseudonymous sender/account lookup identifiers.
  - [x] Connect verified text events to atomic canonical sender admission while
    treating authenticated duplicate deliveries idempotently.
  - [x] Resolve the downstream processor bearer token through local
    reference-only secret custody without an unguarded string copy.
  - [x] Reject signed webhook events older than a deployment-owned maximum age
    before any batch storage mutation.
  - [x] Define a framework-neutral webhook HTTP policy with constant-time
    subscription verification, bounded challenges, and non-enumerating sender
    rejection outcomes.
  - [x] Ship a narrowly scoped Axum gateway binary that receives the channel
    database, deployment-owned WhatsApp secrets, and only the record-cipher
    capability needed to seal its durable inbox.
  - [x] Resolve distinct app-signature, sender-pseudonym, and subscription
    secrets through any deployment-selected secret resolver.
    - [x] Make the shipped gateway startup consume the local resolver rather
      than reading and copying raw secret strings itself.
    - [x] Let self-hosted operators select validated environment or protected
      file references without placing secret values in gateway configuration.
  - [x] Package the gateway as an opt-in hardened Compose overlay with a
    loopback-only host port and documented TLS proxy boundary.
    - [x] Mount WhatsApp authentication, binding, verification, and downstream
      processor credentials as owner-only files without raw Compose
      environment interpolation.
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
    - [x] Bound and zeroize serialized message delivery requests and
      acknowledgement response buffers.
    - [x] Publish a strict language-neutral processor message schema and
      secret-free fixture for non-Rust bot and agent implementations.
      - [x] Compile-test the Rust HTTP processor body against the exact
        published language-neutral fixture.
      - [x] Align canonical identity and non-blank text bounds across the Rust
        authenticated-message constructor and published JSON Schema.
      - [x] Require a bounded JSON acknowledgement tied to the exact protocol
        version and channel event before completing inbox delivery.
      - [x] Add zero-dependency TypeScript helpers that strictly parse the
        published message and create event-bound acknowledgements.
      - [x] Add standard-library-only Python helpers with the same strict
        message and acknowledgement contract.
      - [x] Add dependency-free Kotlin/JVM typed processor messages and
        event-bound acknowledgements with executable validation coverage.
      - [x] Add strict Swift Codable processor messages and acknowledgements
        with exact-key decoding and executable multibyte-limit coverage.
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
  - [x] Redact authenticated message text, platform event/lookup identifiers,
    and canonical identities from shared channel-contract diagnostics.
    - [x] Redact exact authenticated message receipt timelines and enforce
      reviewed debug output for every shared transport-contract struct.
  - [x] Reuse the authenticated-channel contract for explicit iMessage
    extension and mobile-share ingestion without claiming conversation
    interception.
  - [x] Add a strict signed-envelope adapter for explicit mobile shares with
    bounded content, pseudonymous device binding, freshness checks, and
    durable encrypted-inbox admission.
  - [x] Add administrator-authorized CLI enrollment and revocation for mobile
    devices without persisting raw account identifiers, device identifiers, or
    lookup secrets.
    - [x] Resolve stable WhatsApp and mobile-share binding keys through the
      same reference metadata used by their gateway processes.
  - [x] Expose the signed mobile-share boundary through a narrowly scoped
    companion HTTP service.
    - [x] Resolve distinct signing and pseudonymous-binding credentials from
      validated environment or protected-file references.
  - [x] Package the mobile-share gateway in a loopback-only hardened Compose
    overlay with no broad memory API credential or default principal.
    - [x] Mount mobile signing and binding-pseudonym credentials as owner-only
      files without raw Compose environment interpolation.
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
- [x] Community provider and agent adapters.
  - [x] Add a transport-injectable Mem0 OSS semantic mapping layer with
    pseudonymous workspace partitions, exact canonical ID/version metadata,
    replacement, bounded search, and version-aware deletion semantics.
    - [x] Redact Mem0 provider IDs, canonical identities, and keyed binding
      material from diagnostics and enforce the invariant statically.
    - [x] Add an authenticated, redirect-free, proxy-free, bounded HTTP
      transport for Mem0 OSS exact add, list, search, and deletion operations.
      - [x] Bound serialized requests and preserve zeroizing body ownership
        through direct HTTP transmission.
      - [x] Keep bounded provider response bodies in zeroizing storage through
        canonical metadata decoding.
      - [x] Reject provider record collections above the negotiated
        1,000-record ceiling before canonical mapping.
      - [x] Permit plaintext HTTP only for literal loopback IP addresses,
        rejecting remappable local hostnames consistently across sidecars.
    - [x] Expose disposable Mem0 conformance through the CLI with
      deployment-owned secret-reference custody and an explicit
      plaintext-processing acknowledgement.
      - [x] Require a bounded safe external namespace with enough room for a
        fresh random suffix before any provider credential is resolved.
    - [x] Accept already resolved zeroizing API credentials without a
      raw-string validation failure path.
    - [x] Construct the direct adapter from ordered API-key and independent
      workspace-secret references through any deployment secret resolver.
      - [x] Validate and report both Mem0 reference targets in CLI privacy
        diagnostics without requiring raw secret variables.
  - [x] Add a Supermemory v5 semantic adapter with HMAC-derived namespaces,
    deterministic document identity, processing convergence, exact deletion,
    and shared disposable-provider conformance.
    - [x] Redact Supermemory provider IDs, canonical identities, and keyed
      binding material from diagnostics and enforce the invariant statically.
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
      - [x] Bound serialized requests and preserve zeroizing body ownership
        through direct HTTP transmission.
      - [x] Zeroize bounded response bodies after decoding and stream past
        arbitrary deletion error objects without retaining their payloads.
      - [x] Classify credential failures and permanent provider rejection
        separately from transient timeout, throttling, and server failures.
    - [x] Expose disposable Supermemory conformance through the CLI with
      deployment-owned secret-reference custody and explicit plaintext
      acknowledgement.
      - [x] Require exact provider-identity confirmation before replacement or
        deletion can complete.
    - [x] Accept already resolved zeroizing API credentials without a
      raw-string validation failure path.
    - [x] Construct the direct adapter from ordered API-key and independent
      workspace-secret references through any deployment secret resolver.
      - [x] Validate and report both Supermemory reference targets in CLI
        privacy diagnostics without requiring raw secret variables.
  - [x] Generate a secret-reference-only local MCP configuration for OpenCode
    using its command-array and environment-substitution contract.
  - [x] Enforce one bounded control-free executable-command contract before
    rendering any supported agent's TOML or JSON MCP configuration.
  - [x] Encode bounded control-free command and argument invariants in the
    implementation-independent stdio connection manifest schema.
  - [x] Generate reference-only credential environment contracts for clients
    with documented interpolation, an inherited-environment Zed configuration,
    and the implementation-independent bot manifest.
    - [x] Expose a schema-versioned machine-readable catalog of supported
      agent clients, configuration formats, and secret-reference environment
      modes.
      - [x] Publish a strict portable JSON Schema and canonical fixture, with
        the CLI serializer pinned to the fixture.
      - [x] Prove every advertised client has a working secret-safe
        configuration renderer.

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
  - [x] Provide a deterministic, clean-revision security-review manifest with
    SHA-256 inventory and an external-review evidence checklist.
    - [x] Cover every tracked regular file, including the manifest generator,
      application entry points, adapters, deployment assets, and static gates.
    - [x] Support non-overwriting detached Ed25519 reviewer attestations with
      exact-byte tamper detection and independently trusted public keys.
      - [x] Enforce clean manifests, owner-only private keys, regular files,
        and non-symbolic output directories before signing.
      - [x] Reject invalid UTF-8, control-bearing, traversal, and ambiguous
        cross-platform paths before inventory generation or signing.
      - [x] Create a new private attestation directory atomically and
        revalidate the copied manifest bytes before hashing and signing.
      - [x] Require the manifest revision, complete Git inventory, byte
        lengths, and hashes to match a clean checkout before attestation.
    - [x] Define and validate a content-free independent-review result binding
      reviewer independence, manifest digest, scope, aggregate findings, and
      disposition without publishing confidential vulnerability details.
      - [x] Keep the public JSON Schema and executable verifier aligned on
        canonical timestamps, bounded text, and disposition semantics.
      - [x] Sign the linked manifest and review disposition with the same
        reviewer key and verify both signatures, checksums, revision, digest,
        and file-count binding as one portable bundle.
        - [x] Reject undeclared bundle artifacts, ambiguous checksum records,
          and unbounded signature or public-key inputs before verification.
        - [x] Require the verified independent-review bundle in strict
          production-readiness checks rather than silently omitting it.
- [x] Backup, restore, migration, revocation, and deletion have executable
  local-alpha coverage.
