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
  - [x] Bound and validate portable environment, file, and external
    secret-manager references before storing configuration.
    - [x] Make secret references opaque with source-specific read-only
      accessors so integrations cannot construct unvalidated variants.
    - [x] Add a pluggable zeroizing resolver port plus a protected local
      environment and secret-file implementation.
      - [x] Resolve validated provider credential lists atomically from the
        caller's selected local or external resolver.
  - [x] Bound and deduplicate each provider profile's credential-reference
    list before any secret-manager resolution.
  - [x] Make validated provider profiles opaque so callers cannot bypass
    endpoint, placement, or credential-reference invariants.
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
      - [x] Create file-backed Unix keyring databases owner-only and reject
        permissive, non-regular, or symbolic-link targets.
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
- [x] Fail closed when REST or local MCP generated-identifier sequences are
  exhausted instead of reusing saturated memory, event, or disclosure IDs.
- [x] Require a representable strict successor for every optimistic record
  version and canonical event sequence across services and storage adapters.
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
    - [x] Resolve client credentials through the deployment-selected secret
      resolver without fixed environment-variable names.
  - [x] Map every current MCP tool to one narrow OAuth scope and fail closed
    for unknown tools.
  - [x] Add transport-neutral HTTP authorization middleware with strict bearer
    parsing, trusted-origin checks, fail-closed tool lookup, and per-request
    reauthentication.
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
  - [x] Add a bounded session registry with URL-safe identifiers,
    duplicate/capacity controls, per-request revalidation, and authenticated
    deletion, reclaiming expired capacity before accepting new sessions.
    - [x] Separate termination authorization from deletion commit so an HTTP
      transport can retain the local binding until downstream confirmation.
  - [ ] Serve Streamable HTTP through the official Rust MCP SDK.
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
- [x] Require every future context storage adapter to implement disclosure
  persistence through compile-time composite repository capabilities.
- [x] Prove cross-tenant denial across SQLite user-facing read paths.
- [x] Require workspace identity for internal projection-job lookups.
- [ ] Prove cross-tenant denial across every future adapter read path.
  - [x] Cover every currently implemented PostgreSQL tenant-facade point and
    collection read with a mismatched workspace before pool access.
- [ ] Provide the hosted PostgreSQL adapter with row-level security.
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
    - [x] Require prepared `set_config(..., $1, true)` tenant bootstrap,
      exact context read-back, and pooled-connection leakage coverage.
  - [x] Run a live PostgreSQL two-tenant CI proof covering scoped reads,
    denied cross-tenant writes, and fail-closed missing tenant context.
  - [ ] Implement the Rust PostgreSQL repository adapter and live two-tenant
    integration suite.
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
      - [x] Implement tenant-pinned member-scope grant insertion, bounded
        listing with closed scope decoding, and audited exact deletion.
      - [x] Add tenant-verified latest key-rotation and provider-receipt reads
        with strict row correlation and bounded recipient reconstruction.
        - [x] Complete the tenant-pinned `KeyRotationRepository` with atomic
          optimistic completion, receipt/recipient writes, and audit evidence.
      - [x] Atomically remove members, revoke all stored scopes, serialize the
        next required key generation, and persist both lifecycle audit events.
      - [x] Compose PostgreSQL membership, scope, and key-rotation ports through
        client authorization, including fail-closed pending-rotation denial.
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
        - [x] Add authenticated PostgreSQL exact and bounded per-trip booking
          research reads with researcher and version correlation.
          - [x] Atomically capture encrypted PostgreSQL booking research with
            a researcher-bound canonical event and optimistic stream sequence.
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
      - [x] Resolve and validate the PostgreSQL URL through any deployment
        secret resolver into non-cloneable zeroizing adapter configuration.
        - [x] Reject missing, duplicate, or contradictory `sslmode` values
          before the database driver opens a connection.

## Phase 2 — Development continuity

- [x] Canonical temporal knowledge graph.
  - [x] Define engine-neutral, typed workspace-scoped nodes and relationships
    with separate event/system time, validity windows, provenance, bounded
    aliases, and explicit supersession references.
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
          - [x] Resolve the environment-selected Graphiti bearer credential
            from validated environment or protected-file reference metadata.
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
- [x] Canonically parse and bound bring-your-own provider endpoints, allowing
  plaintext loopback only inside a declared trusted boundary.
- [x] Enforce provider protocol and declared limits at projection and retrieval
  boundaries.
- [x] Versioned HTTP sidecar contract for external semantic providers.
- [x] Secret-safe black-box HTTP sidecar conformance runner.
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
      - [x] Require the completed two-provider evidence set in strict
        production readiness.
    - [ ] Complete independent security review and resolve or explicitly
      accept every finding.
      - [x] Require an approving signed disposition in strict production
        readiness while retaining verification support for changes-required
        review bundles.
      - [x] Require accepted-risk approvals to identify their retained review
        record and contain an actual finding or explicit exclusion.
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
      - [x] Package exact two-provider release evidence through a
        non-overwriting, symlink-rejecting, self-verifying local tool.
      - [x] Replace self-asserted external provenance with a detached provider
        result signature under an operator-selected Ed25519 trust anchor.
        - [x] Define and tamper-test a signed provenance statement binding the
          external maintainer, source revision, result digest, and signing time.
        - [x] Generate canonical provenance deterministically from bounded
          result bytes before external signing.
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
  - [x] Verify registry identity, timestamps, conformance status, and pinned
    native Git evidence in the repository static gate.
    - [x] Represent provider revocation as a signed, timestamped, closed-reason
      state that cannot be attached to an active registry entry.
    - [x] Tamper-test missing, reordered, protocol-mismatched, false-pass, and
      unsafe-namespace conformance evidence.
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
    - [x] Add an authenticated, redirect-free, proxy-free, bounded HTTP
      transport for Mem0 OSS exact add, list, search, and deletion operations.
      - [x] Permit plaintext HTTP only for literal loopback IP addresses,
        rejecting remappable local hostnames consistently across sidecars.
    - [x] Expose disposable Mem0 conformance through the CLI with environment
      secret custody and an explicit plaintext-processing acknowledgement.
      - [x] Require a bounded safe external namespace with enough room for a
        fresh random suffix before any provider credential is resolved.
    - [x] Accept already resolved zeroizing API credentials without a
      raw-string validation failure path.
    - [x] Construct the direct adapter from ordered API-key and independent
      workspace-secret references through any deployment secret resolver.
  - [x] Add a Supermemory v5 semantic adapter with HMAC-derived namespaces,
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
      - [x] Classify credential failures and permanent provider rejection
        separately from transient timeout, throttling, and server failures.
    - [x] Expose disposable Supermemory conformance through the CLI with
      environment-only secrets and explicit plaintext acknowledgement.
      - [x] Require exact provider-identity confirmation before replacement or
        deletion can complete.
    - [x] Accept already resolved zeroizing API credentials without a
      raw-string validation failure path.
    - [x] Construct the direct adapter from ordered API-key and independent
      workspace-secret references through any deployment secret resolver.
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
