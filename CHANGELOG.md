# Changelog

All notable changes to Rembrane will be documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and intends to use semantic versioning after the initial protocol stabilizes.

## [Unreleased]

### Added

- Fail-closed graph-context disclosure receipts recording the exact canonical
  edge revisions, query direction and validity time, verified subject and
  client, and declared purpose before context crosses the application boundary.
- In-memory graph disclosure persistence with duplicate-ID rejection and exact
  canonical workspace, edge-identity, and edge-version correlation.
- SQLite graph disclosure schema and atomic repository support with closed
  direction values, tenant-bound graph foreign keys, and exact canonical edge
  revision verification.
- Tenant-pinned PostgreSQL graph disclosure repository operations with bounded
  batches, duplicate-edge rejection, exact returned-row correlation, and
  rollback on missing or stale canonical revisions.
- Driver-boundary regression coverage proving PostgreSQL graph disclosure
  headers and exact disclosed edge revisions commit in one verified tenant
  transaction.
- Bounded SQLite retention purges now include graph disclosure receipts and
  cascade their exact disclosed-edge evidence in the same transaction.
- Graph-context resolution now requires an explicitly granted memory scope and
  a non-empty disclosure purpose before any provider or repository access.
- Dedicated `rembrane:graph:read` remote authorization scope and
  `rembrane_resolve_graph_context` MCP operation classification.
- Transport-neutral graph-context request and response contracts for reuse by
  MCP, REST, SDK, bot, and local integrations.
- Application bridge from the transport-neutral graph request to provider
  traversal, with principal substitution denial and disclosure identity
  returned only after evidence commits.
- MCP `rembrane_resolve_graph_context` tool with explicit temporal direction,
  scope, purpose, and candidate bounds, using the configured native or
  Graphiti provider and returning canonical edge revisions.
- Executable stdio MCP coverage for graph-scope denial and persisted
  disclosure evidence from an authorized empty native-provider neighbourhood.
- Authenticated REST graph-context resolution using the same transport-neutral
  contract, configured provider selection, canonical edge checks, and
  disclosure-before-response boundary as MCP.
- Generic REST context resolution now denies omitted-scope requests unless the
  authenticated connection explicitly holds global read authority.
- Typed TypeScript and standard-library Python graph-context client operations
  targeting the exact authenticated REST route.
- Swift and Kotlin graph-context client operations with executable checks for
  the exact route, bearer authorization, and serialized request body.
- REST black-box coverage for denied graph scopes and successful empty
  neighbourhood disclosures against a canonical tenant node.
- Bounded shared-workspace invitation validity with persisted creation and
  expiry time, a 30-day maximum lifetime, and fail-closed acceptance at the
  expiry boundary.
- Atomic expired-invitation replacement that preserves terminal audit state
  while releasing the one-pending-invitation uniqueness slot.
- Atomic content-free administrative audit evidence for shared-workspace
  invitation creation, acceptance, and revocation.
- Bounded owner/admin-only shared-workspace invitation listing with optional
  status filtering, deterministic ordering, and tenant-isolation proofs across
  in-memory and SQLite repositories.
- Local CLI invitation listing with bounded results, closed status filters,
  management-role authorization, and structured lifecycle metadata.
- Authenticated REST invitation listing with owner/admin authorization,
  optional closed status filtering, bounded results, and a portable OpenAPI
  response contract.
- TypeScript, Python, Swift, and Kotlin invitation-listing operations with
  percent-encoded tenant identifiers and exact authenticated GET-route tests.
- Postman and shell REST acceptance coverage for bounded status-filtered
  invitation listing, lifecycle metadata, and cross-workspace denial.
- A driver-neutral PostgreSQL transaction boundary that exposes repository
  queries only after parameterized transaction-local tenant setup and exact
  canonical read-back, with rollback on mismatch, failure, or dropped work.
- Per-operation PostgreSQL tenant-context revalidation that immediately rolls
  back and permanently closes a transaction after missing or mismatched RLS
  identity.
- A PostgreSQL pool boundary that begins and verifies a new transaction for
  every workspace operation, including sequential cross-tenant connection
  reuse.
- Typed PostgreSQL workspace lookup through the verified tenant transaction,
  with exact identifier matching, closed workspace-kind decoding, bounded
  cardinality, and commit-on-success behavior.
- Typed PostgreSQL membership lookup with exact tenant/principal correlation,
  closed role and lifecycle-status decoding, bounded cardinality, and
  rollback-on-invalid-row behavior.
- Deterministic PostgreSQL active-membership enumeration capped at 10,000
  canonical principals, rejecting duplicate, cross-tenant, or non-active rows
  before deriving authorization or key-rotation recipient sets.
- Tenant-visible PostgreSQL principal lookup with exact requested/returned
  identity correlation and bounded cardinality under membership-mediated RLS.
- Tenant-verified PostgreSQL membership insertion and lifecycle replacement
  with canonical role/status encoding, exact affected-row enforcement, and
  rollback unless the mutation commits successfully.
- Complete PostgreSQL `MembershipRepository` application-port implementation
  with driver-neutral failure classification, duplicate and constraint
  semantics, opaque storage failures, and not-found replacement handling.
- PostgreSQL `AdministrativeAuditRepository` support with atomic append,
  bounded chronological reads, tenant and duplicate correlation, and closed
  decoding for every supported administrative action and target kind.
- PostgreSQL retention-policy lookup with exact tenant correlation, bounded
  cardinality, validated policy restoration, and explicit `NULL`-to-forever
  period decoding.
- Atomic PostgreSQL retention-policy insertion and optimistic replacement with
  strict successor checks, nullable forever-period parameters, exact affected
  rows, and mandatory administrative audit evidence.
- PostgreSQL exact legal-hold lookup and active-hold enumeration capped at
  10,000, with tenant/identifier correlation, duplicate rejection, and closed
  active/released lifecycle restoration.
- Complete PostgreSQL `RetentionRepository` support with atomic audited
  legal-hold placement, strict-successor release, nullable terminal fields,
  exact affected-row checks, and tenant-pinned application access.
- PostgreSQL `MemberScopeGrantRepository` support with tenant-pinned atomic
  audited mutations, bounded deterministic reads, duplicate rejection, and
  closed global/domain/entity/activity scope decoding.
- Tenant-verified PostgreSQL key-rotation reads with closed lifecycle
  restoration, exact receipt identity correlation, and provider receipt
  reconstruction capped at 10,000 canonical recipients.
- Complete PostgreSQL `KeyRotationRepository` support with tenant-pinned,
  generation-checked atomic completion plus provider receipt, canonical
  recipient, and administrative audit persistence.
- PostgreSQL `MemberLifecycleRepository` support with workspace-row
  serialization, optimistic member removal, full scope revocation, required
  key-rotation creation, and paired lifecycle audit evidence in one transaction.
- End-to-end PostgreSQL client-authorization composition proving role-filtered
  write permissions, explicit member scopes, and fail-closed denial while a
  workspace key rotation remains required.
- A dedicated tenant-and-cipher PostgreSQL `MemoryRepository` facade for exact
  lookup and subject enumeration, with bounded reads, authenticated decryption,
  and strict outer-row/domain-payload identity and version correlation.
- PostgreSQL `EventRepository` support on the tenant-and-cipher facade with
  optimistic contiguous sequence checks, encrypted immutable append, bounded
  ordered reads, and authenticated event metadata correlation.
- PostgreSQL `CanonicalMutationRepository` support with authenticated memory
  and event encryption, optimistic record/stream versions, evidence renewal,
  and pluggable provider projection jobs committed atomically.
- Tenant-pinned PostgreSQL `ProjectionOutboxRepository` support with bounded,
  provider-filtered pending reads, closed job decoding, exact lookup, and
  optimistic status/attempt transitions.
- Projection-worker-compatible PostgreSQL capability composition, exposing
  encrypted memory reads and tenant-pinned outbox operations through one
  cipher-bearing facade without granting key access to administrative stores.
- End-to-end PostgreSQL projection-worker coverage from a pending durable job
  through authenticated memory decryption, native provider indexing, and
  optimistic completion.
- PostgreSQL disclosure persistence on the context-capable tenant facade,
  atomically recording purpose, client, context pack, and exact verified
  memory revisions for privacy-accountable AI context delivery.
- End-to-end PostgreSQL context-resolution coverage proving authenticated
  memory selection and mandatory exact-version disclosure persistence before
  returning personalization context to an AI client.
- Tenant-and-cipher PostgreSQL checkpoint reads for exact latest activity state
  and bounded subject history, with authenticated decryption and strict outer
  row/domain payload correlation.
- Atomic encrypted PostgreSQL checkpoint creation and revision with strict
  successor versions, optimistic canonical event sequencing, and matched
  activity/subject audit payloads.
- Exact-version PostgreSQL checkpoint disclosure receipts with tenant,
  subject, activity, and checkpoint correlation before an external client can
  receive resumable working memory.
- End-to-end PostgreSQL checkpoint-service coverage proving authorized
  activity-scoped decryption and mandatory disclosure commit during agent
  handoff.
- Tenant-and-cipher PostgreSQL trip reads for exact entity lookup and bounded
  owner history, with authenticated decryption and strict tenant, owner,
  identifier, and version correlation.
- Atomic encrypted PostgreSQL trip creation and revision with strict successor
  versions, owner-bound travel events, and optimistic workspace event
  sequencing.
- Tenant-and-cipher PostgreSQL booking-research reads for exact records and
  bounded trip histories, with authenticated decryption and strict tenant,
  trip, researcher, identifier, and version correlation.
- Atomic encrypted PostgreSQL booking-research capture with researcher-bound
  canonical events and optimistic workspace event sequencing.
- Exact-version PostgreSQL travel disclosure persistence with verified trip
  ownership, correlated booking-research revisions, freshness classifications,
  and explicit source-reference and sensitive-profile inclusion flags.
- End-to-end PostgreSQL travel-context resolution for shared-workspace readers,
  preserving canonical trip ownership while recording the authorized
  disclosure subject and client.
- Tenant-and-cipher PostgreSQL knowledge-graph reads for exact nodes, exact
  edges, and direction-aware temporal neighbourhoods with authenticated
  decryption, bounded results, and strict endpoint/version correlation.
- Encrypted PostgreSQL knowledge-node and edge creation/revision with strict
  successor versions, tenant pinning, temporal metadata, and preserved
  endpoint/relation lineage.
- Tenant-pinned PostgreSQL graph projection outbox support with idempotent
  node/edge resources, bounded provider-filtered reads, closed decoding, and
  optimistic lifecycle transitions.
- Atomic PostgreSQL canonical graph mutations that validate projection batches
  before committing encrypted node or edge revisions and provider outbox jobs
  together.
- End-to-end PostgreSQL graph projection worker coverage that decrypts the
  exact canonical node, indexes it through the native graph provider, and
  completes the optimistic durable outbox lifecycle.
- Pre-pool cross-workspace denial coverage across PostgreSQL memory, event,
  checkpoint, trip, booking-research, knowledge-graph, retention, and graph
  projection read ports.
- Remote MCP consuming dispatch now carries the exact host and optional browser
  origin that passed OAuth transport authorization, alongside negotiated
  content headers, identity, invocation, and the zeroizing request body.
- Authorized remote MCP event-stream dispatch now preserves the same validated
  public host and browser-origin context through its consuming asynchronous
  SDK handoff.
- Supermemory retrieval, readiness, and exact deletion now reject provider
  document-identity substitution instead of trusting uncorrelated canonical
  memory metadata returned by the external index.
- Mem0 projections now include a deployment-keyed HMAC binding over workspace,
  memory, and version identity; search, replacement, and deletion fail closed
  on missing or altered bindings. Existing unbound namespaces require reindex.
- Supermemory projections now carry the same deployment-keyed workspace,
  memory, and version binding, preventing forged revision metadata beneath an
  otherwise valid deterministic document pseudonym. Existing unbound
  namespaces require reindex.
- A graph-context application service that treats native or Graphiti
  candidates as untrusted hints and returns only exact canonical edges matching
  workspace, version, requested endpoint direction, and temporal validity.
- Graph-context resolution now requires a connection-derived read grant whose
  workspace exactly matches the graph query, rejecting mismatches before any
  provider or storage access.
- PostgreSQL invitation lookup and bounded deterministic listing with optional
  status filtering, numeric lifetime decoding, terminal-state restoration,
  and exact tenant/invitation correlation.
- Complete PostgreSQL `InvitationRepository` mutations with atomic expired-row
  replacement, optimistic lifecycle transitions, membership activation,
  content-free administrative audit evidence, and closed aggregate validation.
- Repository-owned invited-principal integrity checks across memory, SQLite,
  and PostgreSQL adapters, removing the invitation service's incompatible
  global principal lookup under tenant-isolated RLS.
- A workspace-pinned PostgreSQL application facade for membership and
  invitation ports that rejects cross-workspace calls before opening a pooled
  transaction.
- A narrow `WorkspaceReadRepository` application port, allowing PostgreSQL
  invitation services to use tenant-scoped workspace lookup without access to
  privileged identity/workspace provisioning credentials.
- A separate PostgreSQL provisioning-pool contract and rollback-on-drop
  transaction guard for first-principal/workspace bootstrap, keeping
  privileged credentials out of ordinary tenant request paths.
- Atomic PostgreSQL personal and shared workspace provisioning with closed
  aggregate validation, exact existing-owner correlation, and exact affected
  row enforcement.
- A target-workspace-bound PostgreSQL control-plane store implementing the
  complete `WorkspaceRepository` while confining privileged principal lookup
  and provisioning credentials outside runtime tenant stores.

### Changed

- Corrected the local-alpha exclusion boundary to distinguish shipped OS key
  providers, invitation and rotation flows, OAuth contracts, and PostgreSQL
  RLS proofs from the remaining cloud-KMS sidecars, official remote MCP
  transport, Rust PostgreSQL adapter, and independent-audit work.
- Local CLI commands for creating shared workspaces and creating, accepting,
  or revoking bounded role-specific invitations.
- Authenticated REST invitation creation, acceptance, and revocation,
  including a pre-membership connection state with no memory scopes or
  mutation permissions.
- REST acceptance coverage for bounded invitation creation and revocation plus
  a zero-memory-authority invited connection accepting into atomic active
  membership, including persisted terminal-state and audit assertions.
- TypeScript, Python, Swift, and Kotlin SDK operations for authenticated
  shared-workspace invitation creation, acceptance, and revocation.
- A machine-verifiable Memory Provider Protocol compatibility lock covering
  canonical schemas, HTTP binding, conformance profiles, and lifecycle
  fixtures, with CI rejection of unreviewed wire-surface drift.
- An unconditional negative compatibility-lock fixture proving a tampered
  canonical Memory Provider schema fails verification.
- A schema-versioned machine-readable MCP client catalog covering Codex,
  Claude Code, Gemini CLI, Cursor, VS Code, Zed, OpenCode, and the generic bot
  manifest, including each client's configuration and secret-reference
  environment mode.
- A strict portable schema and canonical fixture for the MCP client catalog,
  with the CLI serializer pinned to the published representation.
- Catalog-to-renderer parity checks preventing unsupported or raw-key-bearing
  agent configurations from being advertised.
- A parameter-bound PostgreSQL tenant-session contract with exact context
  read-back requirements and a live pooled-connection leakage regression.
- A typed reference-only PostgreSQL connection profile with explicit
  full-verification versus trusted-boundary transport policy and bounded pool
  capacity, without a derived debug representation that could expose its
  secret locator in logs.
- Deployment-selected PostgreSQL URL resolution into a bounded, validated,
  non-cloneable, non-debuggable zeroizing adapter-construction value.
- Fail-closed agreement between declared PostgreSQL transport policy and one
  exact resolved `sslmode`, preventing URL parameters from silently weakening
  verified transport.
- A Zed local MCP configuration that safely inherits the application process
  environment instead of embedding unsupported `${VAR}` interpolation or raw
  credentials in settings.
- End-to-end generated-configuration coverage for Cursor, VS Code, Zed, and
  OpenCode in addition to Codex, Claude Code, Gemini CLI, and generic launchers.
- Reference-only workspace-key and HTTP key-provider credential locators in
  every generated MCP client configuration, removing raw key and bearer-token
  variable requests from launcher manifests.
- Checked optimistic version and event-sequence progression across application,
  in-memory, SQLite, REST, and CLI paths, rejecting exhaustion instead of
  accepting repeated saturated revisions.
- Fail-closed REST and local MCP generated-identifier exhaustion handling,
  preventing saturated counters from reusing memory, event, checkpoint,
  travel, or disclosure identities.
- Fail-closed Graphiti request-correlation exhaustion handling that prevents
  long-running provider connections from wrapping and reusing request IDs.
- PostgreSQL authenticated channel replay, active-member sender bindings, and
  an encrypted leased inbox with immutable identity and monotonic delivery,
  retry, quarantine, and requeue transitions, plus a static table-inventory
  parity gate preventing hosted-schema omissions.
- PostgreSQL encrypted temporal knowledge nodes and edges with validity
  indexes and an idempotent provider projection outbox under forced RLS.
- PostgreSQL travel-continuity tables for encrypted trips and booking research,
  checkpoint disclosures, and receipts that explicitly record sensitive
  source-reference and traveler-profile disclosure.
- PostgreSQL shared-workspace administration tables for invitations, scoped
  member grants, key rotation, retention, legal holds, and append-only audit,
  with RLS applied only after all numbered schema migrations.
- A canonical PostgreSQL base schema for encrypted memories, evidence,
  checkpoints, disclosure receipts, projection jobs, and immutable workspace
  events, plus membership-scoped principal RLS.
- Reference-only HTTP key-provider bearer configuration in the WhatsApp,
  channel-worker, and mobile-share Compose services, with a static regression
  gate preventing raw credential interpolation.
- Shared protected-secret staging for the Graphiti sidecar, followed by an
  explicit privilege drop to its dedicated service user.
- Container-entrypoint staging of mounted secrets into a bounded owner-only
  runtime tmpfs before privilege drop, avoiding dependence on Compose
  implementations preserving requested file ownership and modes.
- Read-only root filesystems and bounded temporary mounts for the canonical
  REST service, WhatsApp gateway, channel worker, and mobile-share gateway.
- File-backed Cloudflare Tunnel token injection through `--token-file`, with a
  version-pinned non-root container and no token in rendered command arguments.
- A validated container startup mode for least-privileged channel services
  that skips personal-workspace bootstrap and no longer requires injecting a
  default principal into gateways or workers.
- Owner-only mobile-share Compose secrets for request signing and stable
  account/device pseudonymization credentials.
- Owner-only WhatsApp and channel-processor Compose secrets for webhook
  authentication, sender pseudonymization, subscription verification, and
  downstream delivery credentials.
- Protected local workspace-key references and owner-only Compose mounts for
  both the development encryption key and REST bearer token, removing their
  raw values from service environment interpolation.
- Protected Graphiti Neo4j-auth and model-provider key references, including
  file-backed Compose injection and removal of raw credentials from service
  environment metadata.
- Protected environment or file reference resolution for the Python Graphiti
  sidecar bearer credential, plus one mode-restricted Compose secret shared
  with the Rust projection worker instead of environment interpolation.
- Protected local bearer-token reference resolution for environment-selected
  portable Memory Provider HTTP composition, with zeroizing configuration
  ownership and opaque resolution failures.
- Reference-only REST API bearer-token configuration with protected local
  resolution and bounded RFC-compatible token validation.
- Protected-file or environment reference resolution for stable WhatsApp and
  mobile-share binding keys during administrative CLI onboarding.
- Protected local reference resolution for customer HTTP key-provider bearer
  credentials with zeroizing configuration ownership.
- A consuming remote-MCP dispatch handoff that transfers verified tenant
  identity, classified invocation, and the exact OAuth-authorized zeroizing
  request body together to the eventual official SDK transport.
- An owned authorized remote-MCP dispatcher port with regression coverage
  proving exact tenant, operation, tool, and request-body transfer.
- A dependency-free asynchronous future contract for remote-MCP dispatchers,
  avoiding blocking at the eventual official SDK Tower boundary.
- One owned Axum authorize-and-dispatch operation that consumes the exact
  request proof and preserves typed HTTP authorization versus SDK dispatch
  failures.
- Fail-closed duplicate rejection for remote MCP `Content-Type`, `Accept`, and
  `MCP-Protocol-Version` headers before OAuth body authorization.
- Pre-authorization MCP content negotiation enforcing `application/json`
  requests and clients that accept both JSON and event-stream responses, with
  protocol-correct 415 and 406 failures.
- Owned propagation of validated content type, response negotiation, and MCP
  protocol version through the same authorization proof as tenant identity and
  exact request bytes.
- Forward-compatible but bounded `YYYY-MM-DD` validation for optional
  `MCP-Protocol-Version` values before OAuth work and SDK dispatch.
- An owned stateless Streamable HTTP event-stream authorization boundary with
  GET-specific `text/event-stream` negotiation and the same bearer, Host,
  Origin, session, and tenant checks as POST.
- An owned event-stream proof coupling verified tenant identity with the exact
  negotiated `Accept` and optional bounded MCP protocol-version values.
- An asynchronous consuming event-stream dispatcher port so the official SDK
  can open GET streams only from tenant-bound authorization proofs.
- One owned Axum authorize-and-open operation for stateless MCP event streams,
  preserving typed HTTP authorization versus SDK stream-dispatch failures.
- In-memory Axum integration coverage routing two OAuth workspaces through the
  asynchronous dispatcher and proving dispatched tenant identity cannot bleed
  across requests.
- Concurrent in-memory Axum event-stream routing coverage proving stateless
  GET dispatch preserves separate OAuth workspace identities and rejects an
  untrusted browser origin before opening a stream.
- Socket-free Memory Provider HTTP request-construction tests covering exact
  methods, encoded paths and queries, bearer and correlation headers, direct
  JSON payloads, and body-free reads under restricted development sandboxes.
- Hardened OAuth introspection HTTP transport validation with parsed HTTPS
  endpoints, bounded control-free credentials and bearer tokens, disabled
  environment proxies, and socket-free exact RFC 7662 request tests.
- OAuth introspection transport construction from validated remote MCP
  profiles through any deployment-selected secret resolver, retaining the
  resolved client secret in zeroizing storage across every failure path.
- Graphiti composition from validated provider profiles through pluggable
  secret resolvers, with provider-kind, credential-cardinality, and explicit
  plaintext-policy checks before resolution.
- Protected local Graphiti bearer-token references for environment-selected
  knowledge-graph worker composition.
- Portable Mem0 and Supermemory composition from validated provider profiles
  through pluggable secret resolvers, retaining zeroizing credentials through
  HTTP construction and enforcing negotiated privacy policy at discovery.
- Direct Mem0 and Supermemory HTTP constructors for already resolved
  zeroizing API keys, with legacy string constructors entering zeroizing
  custody before endpoint, credential, or client validation can fail.
- Direct Mem0 and Supermemory semantic-adapter construction from validated
  two-secret profiles through pluggable resolvers, keeping API credentials
  separate from independent workspace-pseudonym keys.
- A canonical key-provider profile kind and configured-cipher construction
  through pluggable secret resolvers, transferring resolved bearer authority
  directly into zeroizing HTTP transport custody.
- Reference-only WhatsApp verifier configuration through pluggable secret
  resolvers, requiring distinct app-signature, sender-pseudonym, and
  subscription credentials and retaining only derived HMAC keys.
- Shipped WhatsApp gateway startup through reference-only configuration and
  the protected local secret resolver, removing direct raw-secret handling
  from the executable.
- Portable `env:`, `file:`, and `external:` secret-reference parsing, with
  optional WhatsApp gateway locator variables and environment-backed defaults.
- Reference-only channel processor bearer-token configuration with protected
  local resolution and zeroizing ownership through HTTP transport setup.
- Fail-closed OAuth introspection claim bounds covering audience cardinality,
  issuer and identity sizes, scope size, and control-character rejection
  before claims become canonical tenant identity.
- Transport-neutral remote-token claim limits shared by every verifier,
  including duplicate-audience rejection and bounded issuer, resource, subject,
  client, and workspace identities before verified access is constructed.
- An 8 KiB transport-neutral bearer-token ceiling enforced before signature
  verification or authenticated introspection.
- An 8 KiB outer remote-MCP header ceiling applied uniformly to credential,
  Host, Origin, session, content-negotiation, and protocol-version headers
  before parsing or authentication.
- Parsed and canonically serialized remote-MCP deployment URLs with bounded
  endpoint, OAuth client ID, trusted-origin count, and individual-origin sizes,
  rejecting malformed ports and normalization ambiguity before startup.
- Canonically parsed and bounded bring-your-own provider endpoints that reject
  stored whitespace and URL normalization ambiguity while permitting literal
  loopback HTTP only for providers declared inside the trusted boundary.
- Bounded portable secret references for environment variables, protected
  files, and external secret-manager keys, rejecting whitespace ambiguity,
  controls, invalid provider identifiers, and resource-exhaustion inputs.
- Bounded duplicate-free credential-reference lists for bring-your-own
  provider profiles, preventing ambiguous precedence and amplified
  secret-manager resolution.
- Opaque validated provider profiles with read-only accessors, preventing
  integrations from bypassing endpoint, placement, and credential-reference
  construction invariants through public fields.
- Opaque validated secret references with source-specific read-only accessors,
  preventing direct construction of unvalidated environment, file, or external
  secret-manager variants.
- A pluggable zeroizing secret-resolver port with a local environment and
  protected-file adapter that bounds values, rejects nulls, unsafe permissions,
  non-regular files, and symlinks, and leaves external managers replaceable.
- Ordered all-or-error provider credential resolution through any secret
  resolver, zeroizing already resolved values when a later reference fails.
- A transport-injectable Mem0 OSS semantic adapter mapping authorized
  projections into HMAC-pseudonymous workspace partitions while preserving
  canonical memory IDs, versions, replacement, bounded ranking, and
  version-aware deletion semantics.
- An authenticated Mem0 OSS HTTP transport with `X-API-Key` custody in
  zeroizing memory, HTTPS-or-loopback enforcement, disabled redirects and
  environment proxies, strict timeouts, bounded JSON, exact non-inferred
  projection writes, and safely encoded deletion paths.
- CLI execution of the shared semantic conformance suite against an
  operator-owned disposable Mem0 instance, gated by explicit plaintext
  acknowledgement and environment-only credentials.
- Fail-closed external provider conformance namespaces constrained to a
  bounded shell-safe character set before credentials are resolved.
- Literal-IP-only loopback HTTP policy across Mem0, Graphiti, memory-provider,
  key-provider, and channel-processor transports, preventing remapped
  `localhost` names from bypassing HTTPS requirements.
- A customer-KMS deployment contract mapping the operation-only key-provider
  boundary to AWS KMS, Azure Key Vault/Managed HSM, and Google Cloud KMS while
  keeping cloud identity and key material inside the customer sidecar.
- A Supermemory v5 adapter decision defining pseudonymous namespace mapping,
  asynchronous projection convergence, exact deletion, plaintext boundaries,
  and the evidence required before compatibility promotion.
- Typed Supermemory bring-your-own-provider configuration with referenced
  credentials and consistent rejection of remappable `localhost` HTTP.
- A transport-injectable Supermemory semantic mapping layer with
  pseudonymous namespaces, canonical version replacement, bounded ranking,
  exact deletion, and shared conformance coverage.
- Keyed deterministic Supermemory document IDs generated by the trusted
  mapping layer instead of delegated to provider transports.
- Domain-separated HMAC inputs for Supermemory namespace and document
  pseudonyms.
- Mandatory Supermemory ingestion-readiness confirmation, with incomplete
  processing surfaced as retryable provider failure rather than false
  projection completion.
- Supermemory readiness checks bound to the exact authorized projection,
  enabling canonical ID/version visibility verification through scoped search.
- Strict Supermemory wire decoding for canonical metadata, finite bounded
  scores, response cardinality, and one exact deletion success.
- Correct decoding of Supermemory records containing both internal and
  caller-defined IDs, preferring deterministic `customId` for deletion.
- An authenticated Supermemory v5 HTTP transport with zeroizing bearer
  custody, HTTPS-or-literal-loopback enforcement, disabled redirects and
  proxies, bounded JSON, exact upsert/delete identities, and scoped readiness
  polling.
- CLI execution of shared semantic conformance against an operator-owned
  disposable Supermemory v5 namespace with environment-only secrets and
  explicit plaintext consent.
- Exact Supermemory deletion confirmation, treating partial or omitted
  provider identities as retryable failures.
- Local validation proving generated Supermemory namespace pseudonyms satisfy
  the provider's bounded safe-character contract.
- Path-safe deterministic Supermemory document pseudonyms that prevent
  canonical memory identifiers from entering provider URLs.
- Deterministic Supermemory replacement through direct create-or-update
  semantics, removing a bounded pre-delete scan that could miss large
  namespaces.
- Exact Supermemory document retrieval before version-bounded deletion,
  removing the remaining pagination dependency from lifecycle operations.
- Regression coverage proving Supermemory version-bounded deletion never
  falls back to namespace listing.
- Removal of namespace-wide listing from the Supermemory transport contract;
  lifecycle uses exact document identity and retrieval remains bounded search.
- Current Supermemory v5 ingestion compatibility using the caller-defined
  `id` field, with strict bounded response status and identity confirmation.
- Current Supermemory v5 search compatibility using the `query` request field
  for both readiness convergence and semantic recall.
- Correct Supermemory replacement semantics: exact retrieval selects PATCH for
  existing deterministic documents, while POST is limited to first creation
  so retries and corrections do not append stale canonical content.
- Explicit Supermemory `dreaming: "instant"` processing for create and PATCH
  requests, aligning bounded readiness polling with v5 processing behavior.
- Fail-closed Supermemory HTTP status classification that surfaces invalid
  credentials without retry loops and reserves retryable failure for timeout,
  throttling, and server-side availability conditions.
- A public-API-only iMessage app extension reference with explicit text entry,
  review, confirmation, Keychain-held enrollment material, narrow signed
  gateway submission, and an iPhone Simulator type-check gate.
- A reusable Swift mobile-share Keychain enrollment store with bounded
  metadata, minimum signing-key enforcement, generic failure reporting, and
  optional explicit access-group lookup shared by companion and extension
  targets.
- Validated mobile enrollment upsert and idempotent revocation APIs using
  `WhenUnlockedThisDeviceOnly` Keychain accessibility, enabling companion-app
  setup without credentials in shell commands or extension bundles.
- Bounded on-device mobile-share signing-key generation through
  `SecRandomCopyBytes`, preventing companion setup flows from requiring secret
  creation or transfer through a shell or pasteboard.
- Atomic versioned mobile enrollment bundles in Keychain, with bounded binary
  property-list decoding plus read migration and revocation cleanup for the
  earlier independently stored account, device, and signing-key items.
- An Axum-facing remote MCP authorization boundary that rejects duplicate
  credential, host, origin, and session headers, authorizes the exact bounded
  JSON-RPC body, and maps 401/403/503 outcomes into safe HTTP responses before
  official SDK dispatch.
- An owned Axum remote-authorization service that safely reconstructs
  short-lived borrowing authenticators for every request, with an in-memory
  router proof that distinct OAuth tokens retain distinct workspace identity
  and untrusted browser origins fail closed.
- An opaque authorized remote-MCP request object that keeps verified identity,
  classified operation, and the exact bounded JSON-RPC bytes together through
  dispatch, zeroizing the copied request body when released.
- Linux Secret Service workspace-key resolution through the fixed
  `/usr/bin/secret-tool` client, including active/historical keyrings,
  metadata-only agent configuration, and zeroized captured secrets.
- Immediate zeroization guards around OS-keyring subprocess stdout and stderr,
  including non-UTF-8, nonzero-exit, and unexpected-diagnostic failure paths.
- Linux Secret Service lookups bound to service, account, and expected key ID
  so active and historical generations cannot cross-resolve through reused
  account metadata.
- A Windows DPAPI blob-reference contract with generation-specific key IDs,
  bounded local absolute paths, traversal rejection, historical parsing, and a
  dedicated Windows warnings-as-errors CI job.
- Windows CurrentUser DPAPI resolution for active and historical workspace
  keys through a fixed system PowerShell bridge, with key-ID entropy,
  zeroized subprocess output, metadata-only agent configuration, and a live
  Windows CI protect/unprotect round trip.
- Secret-safe OpenCode local MCP configuration generation using the documented
  command-array shape and environment-variable references without embedding
  credential values.
- Fail-closed validation of MCP server executable commands before rendering
  any agent configuration, preventing control-character injection across TOML
  and JSON client formats.
- Bounded control-free command and argument requirements in the portable stdio
  connection manifest, with a requirement that launchers execute directly
  rather than through a shell.
- A modern stateless remote-MCP authorization path that rejects legacy session
  ambiguity while preserving per-request bearer verification, trusted Host and
  Origin checks, strict method/tool classification, and narrow OAuth scopes.
- A bounded pre-dispatch remote-MCP JSON-RPC classifier that rejects batches,
  malformed envelopes, unsupported methods, and unknown or mismatched tools
  before requests can reach the official protocol SDK.
- An atomic stateless body-authorization operation that binds verified OAuth
  identity and narrow scope decisions to the exact classified JSON-RPC bytes.
- A transport-neutral mobile-share verifier for explicit user-selected text,
  with raw-payload HMAC authentication, bounded strict envelopes,
  pseudonymous device binding, freshness enforcement, replay idempotency, and
  optional encrypted durable admission.
- Audited mobile-device binding and revocation through the CLI, deriving
  pseudonymous account/device keys from environment-only raw identifiers and
  deployment secrets.
- A least-privileged loopback-default mobile-share gateway and hardened
  Compose overlay that acknowledge signed explicit shares only after atomic
  encrypted-inbox admission, with a socket-free real-SQLite lifecycle test.
- Reference-only mobile-share gateway credentials with distinct-purpose
  enforcement, protected local resolution, and bounded secret lengths.
- A Swift mobile-share client with an injectable signer boundary so iOS apps
  and share extensions can keep signing keys in platform-controlled storage
  while sending only explicit user-selected content.
- A versioned OpenAPI contract and validated secret-free request fixture for
  independent explicit-share clients, including exact-body signature and
  non-enumerating response semantics.
- A CryptoKit mobile-share signer for the Swift package, validating minimum
  key strength and producing the protocol's exact lowercase HMAC header.
- A Swift explicit-share coordinator for companion apps and public extension
  surfaces, with bounded preflight validation, generated idempotency IDs, and
  submission exclusively through the signed narrow gateway client.
- A reference iOS Share Extension controller that accepts one user-selected
  text item, loads device enrollment material from a shared Keychain group,
  and documents strict public-API and secret-storage boundaries.
- An iPhone Simulator SDK type-check gate for the reference Share Extension,
  with all Swift and Clang compiler caches confined to ephemeral storage.
- A Ring-backed WhatsApp Business webhook boundary that authenticates the raw
  bounded payload before parsing, extracts bounded text events, and derives
  domain-separated keyed account/sender lookup fingerprints.
- A WhatsApp ingestion bridge into atomic canonical sender admission that
  verifies before storage, ignores authenticated duplicate deliveries, and
  fails closed on every other repository error.
- Pre-storage WhatsApp event-age enforcement that rejects stale signed
  deliveries before expired replay receipts could permit renewed admission.
- A framework-neutral WhatsApp HTTP policy with constant-time bounded
  subscription verification and non-enumerating status mapping for unknown or
  revoked senders.
- A standalone narrowly scoped WhatsApp gateway binary with bounded GET
  subscription and POST event endpoints, loopback-safe defaults, configurable
  replay limits, and no API or broad memory authorization.
- An opt-in hardened WhatsApp Compose overlay and operator guide that share
  only the canonical database volume and keep the gateway host port on
  loopback behind a deployment-owned HTTPS proxy.
- Administrator-only WhatsApp sender onboarding through the CLI, consuming
  raw platform identifiers from protected environment variables while
  persisting and reporting no raw or derived identifiers.
- WhatsApp onboarding support for binding any active workspace member by a
  distinct administrator, with explicit lookup-secret zeroization on malformed
  identifier paths.
- Atomic administrator-authorized channel-binding creation and revocation with
  content-free append-only audit evidence and explicit CLI lifecycle commands.
- A socket-free executable WhatsApp gateway integration test covering a real
  signed payload, active pseudonymous sender binding, SQLite admission, and
  idempotent replay.
- A versioned encrypted channel-inbox schema and portable repository contracts
  for atomic durable admission, tenant-scoped recovery, and monotonic delivery
  completion without plaintext-at-rest fields.
- SQLite durable channel admission that resolves active identity, reserves
  replay, and AEAD-seals message text in one transaction, plus authenticated
  tenant-scoped recovery and one-way completion.
- Executable WhatsApp acknowledgement backed by encrypted durable admission,
  with deployment-selected local, keychain, or customer-key-provider cipher
  configuration and an integration assertion that recovers the queued text.
- A provider-neutral bounded channel-inbox worker contract that passes
  authenticated messages to idempotent bot or agent processors, completes only
  successful deliveries, and leaves failures queued for retry.
- A strict HTTPS-or-loopback channel processor adapter with bearer
  authentication, canonical workspace/principal/client identity, exact event
  idempotency headers, redirect rejection, and bounded responses.
- A configurable per-workspace channel worker executable that decrypts bounded
  inbox batches, delivers them through the HTTP processor, retries failures,
  and persists completion only after success.
- Complete opt-in WhatsApp Compose packaging for both durable webhook ingress
  and per-workspace encrypted-inbox delivery to a cooperative bot endpoint.
- Bounded channel delivery retries with durable availability times, configurable
  attempt limits, and terminal quarantine so poison messages cannot monopolize
  an inbox worker.
- Atomic expiring channel-inbox leases that prevent concurrent workers from
  delivering the same event while automatically reclaiming work after a
  crashed or stalled worker.
- Cryptographically random per-process channel lease ownership, binding
  completion and retry transitions to the current claimant so a stale worker
  cannot mutate a message after another worker reclaims it.
- Processor-declared hard execution bounds and batch-aware lease validation,
  rejecting configurations that could expire while a claimed batch is still
  being delivered.
- Administrator-only content-free channel inbox summaries and a CLI status
  command exposing pending, processing, and quarantined counts without
  decrypting or returning message content.
- Administrator-only single-event quarantine recovery through the CLI, with
  atomic retry reset and append-only content-free audit evidence while leaving
  encrypted message bytes unchanged.
- Domain-separated SHA-256 channel audit target fingerprints that preserve
  content-free evidence while supporting the complete bounded opaque event-ID
  space, including maximum-length identifiers.
- Durable, content-free SQLite channel replay receipts with atomic cleanup,
  fail-closed capacity enforcement, per-platform namespaces, and
  cross-workspace duplicate denial for multi-process gateways.
- Tenant-owned channel sender bindings that resolve keyed pseudonymous account
  and sender identifiers to canonical workspace, principal, and client IDs
  without persisting raw phone numbers.
- Active-membership enforcement and automatic revocation for channel sender
  bindings, preventing suspended or removed principals from retaining gateway
  identity.
- Atomic bound-channel admission that resolves canonical identity and reserves
  replay protection in one transaction, closing membership-revocation races.

### Fixed

- Restored the complete dependency-enabled workspace build by declaring
  previously implicit crate dependencies and enabling rmcp's stdio transport.
- Corrected Memory Provider selector field casing and URL path construction so
  opaque memory and activity identifiers remain one percent-encoded segment.
- Replaced fragile hand-escaped MCP client JSON with structured serialization,
  removed a duplicate API error constructor, and fixed stale test fixtures.
- Added a reproducible application workspace lockfile and pinned `uuid` to a
  Rust-1.88-compatible release.
- Cleared warnings-as-errors Clippy findings across every workspace target,
  including boxed configured-provider variants, explicit wire-field mappings,
  borrowed keychain configuration, and smaller command/API cleanups.
- An immutable, bounded, content-free administrative audit event contract with
  tenant, actor, closed action, opaque target, request correlation, and
  occurrence time while excluding memory content, secrets, and key material.
- Append-only tenant-scoped administrative audit repositories for volatile and
  SQLite storage, including bounded chronological reads and database triggers
  that reject update or deletion.
- Atomic content-free administrative audit evidence for member removal,
  key-rotation requirement, and key-rotation completion in both in-memory and
  SQLite repository transactions.
- Request-correlated scope grants and revocations that commit their
  content-free administrative audit evidence atomically in both storage
  adapters.
- Owner/admin-only retention-policy and legal-hold application services with
  optimistic mutation and request-correlated audit evidence committed in the
  same in-memory or SQLite transaction.
- Tenant-bound authenticated management HTTP endpoints and CLI commands for
  bounded administrative-audit reads, retention-policy updates, and legal-hold
  placement or release.
- Owner/admin-only bounded retention purge planning and SQLite execution with
  resource-specific cutoffs, a global deletion cap, active legal-hold
  blocking, referential-safety checks, and permanent exclusion of append-only
  administrative audit evidence.
- Secret-safe native stdio MCP configuration generators for Cursor, VS Code,
  and Zed alongside the existing Codex, Claude Code, and Gemini CLI formats.
- Complete OpenAPI bindings for administrative-audit reads, retention-policy
  mutation, legal-hold placement and release, and bounded retention purge.
- A zero-dependency TypeScript SDK package with typed declarations,
  HTTPS-or-loopback endpoint enforcement, bearer authentication,
  redirect rejection, bounded JSON responses, management operations, and an
  executable mock-transport test.
- A standard-library-only Python 3.11 SDK with injected transport testing,
  HTTPS-or-loopback endpoint enforcement, redirect rejection, bounded JSON
  decoding, typed API errors, and matching management operations.
- A Swift Package with a `Sendable` injected transport boundary,
  redirect-rejecting ephemeral URLSession transport, HTTPS-or-loopback
  endpoint policy, bounded JSON decoding, typed API errors, and a standalone
  compiled smoke test.
- A dependency-free Kotlin/JVM SDK using the JDK HTTP client with redirects
  disabled, HTTPS-or-loopback endpoint policy, bounded JSON responses, typed
  API errors, injected transport support, and a portable smoke fixture.
- Automated provider-registry evidence validation plus detached Ed25519
  signing and tamper-detection commands that consume private keys only from
  operator-controlled filesystem paths.
- A release workflow that signs the compatibility registry with a
  repository-secret Ed25519 key, verifies the result, removes the ephemeral
  private-key file, and publishes JSON, checksum, signature, and public-key
  artifacts.

### Changed

- Reconciled roadmap completion state with existing workspace, Graphiti,
  Memory Provider, key-provider, and SQLite CI gates so remaining checkboxes
  represent unimplemented or externally gated work.
- Added a pinned Ubuntu 24.04 Kotlin SDK job that requires the hosted
  `kotlinc` and Java toolchains and executes the portable compiler smoke test.
- Preserved remote MCP HTTP authentication outcomes through session
  establishment, request classification, cross-tenant revalidation, bounded
  capacity handling, and authenticated termination.
- Added a framework-neutral remote MCP HTTP gate that validates session
  headers, authorizes every request before protocol dispatch, produces safe
  RFC 9728 bearer challenges, and maps duplicate or exhausted sessions to
  explicit bounded transport outcomes.
- Required exact bounded Host allowlisting at the remote MCP HTTP gate to
  reject DNS-rebinding requests before bearer verification or SDK dispatch.
- Derived the remote MCP Host allowlist and protected-resource challenge from
  one validated public resource profile, preventing deployment-policy drift.
- Added a PostgreSQL forced-RLS foundation using transaction-local workspace
  identity, deny-by-default policies, separate migration/runtime role
  requirements, and static invariant verification.
- Added a live PostgreSQL 17 CI proof for tenant-scoped reads, denied
  cross-tenant writes, source-workspace proposal isolation, and unscoped
  fail-closed behavior.
- Added composite repository capabilities that prevent context, checkpoint,
  and travel read adapters from compiling unless they also implement their
  corresponding disclosure-receipt persistence port.
- Added a strict production-readiness orchestrator covering offline security,
  dependency-enabled Rust/Postman, live PostgreSQL RLS, and container gates,
  with explicit failure for unavailable required infrastructure.
- Added pull-request, main-branch, and scheduled CodeQL analysis for Rust,
  JavaScript/TypeScript, and Python vulnerability patterns.
- Added pull-request dependency review that blocks moderate-or-higher known
  vulnerabilities and incompatible AGPL/SSPL dependency licenses.
- Added static CI hardening and expanded secret detection for risky workflow
  triggers, mutable actions, excessive permissions, shell-download pipelines,
  private keys, cloud credentials, and common service-token formats.
- Added a bounded verified-channel message contract for WhatsApp Business,
  explicit iMessage extensions, and mobile share flows that derives canonical
  tenant identity only from authenticated deployment-owned sender bindings.
- Added bounded channel-event replay protection with future-time rejection,
  fail-closed capacity, expiry, and per-platform event namespaces.
- A versioned per-workspace retention policy contract with separate periods
  for memory, checkpoints, travel research, disclosures, canonical events, and
  administrative audit, including bounded expiry and legal-hold overrides.
- Optimistically versioned in-memory and SQLite retention-policy and legal-hold
  storage with tenant-scoped active-hold lookup.
- A provider-independent, content-free shared-workspace key-rotation
  aggregate with monotonic generations, removal provenance, explicit pending
  state, and opaque key-provider completion identity.
- Atomic in-memory and SQLite member removal that revokes scope grants and
  creates the next tenant-scoped key-rotation generation in the same
  transaction.
- Fail-closed client authorization while a workspace has a required,
  incomplete encryption-key rotation.
- Owner/admin-only, generation-bound key-rotation completion with optimistic
  in-memory and SQLite persistence and opaque key-provider identity.
- Tenant-scoped active-membership enumeration for comparing future
  key-provider rotation receipts against canonical authorized recipients.
- A bounded, content-free key-provider rotation receipt contract binding
  provider and request identity, workspace generation, opaque key identity,
  and a canonical exact recipient set.
- Fail-closed rotation completion unless the provider receipt matches the
  pending workspace generation and exact canonical active-member set.
- Atomic tenant-scoped persistence of validated rotation provider, request,
  generation, opaque key, and recipient evidence alongside completion.
- Optional Key Provider Protocol rotation capability with bounded canonical
  requests and fail-closed provider, request, workspace, generation, and
  recipient receipt correlation.
- Authenticated `/v0.1/rotate` key-provider HTTP transport with strict
  content-free receipt decoding and black-box replay/correlation conformance
  coverage.
- Authorization-first workspace-key rotation orchestration and a `rembrane
  rotate-key` operator command that derives recipients from canonical active
  memberships before invoking a configured customer key provider.
- An authenticated `POST /v1/workspaces/key-rotation` management operation
  with tenant-bound workspace selection and content-free completion output.
- Executable rotation-orchestration coverage proving authorization precedes
  provider side effects and canonical recipients exclude removed members.
- Consumed customer key-provider HTTP configuration for application-owned
  vault, keychain, cloud-secret, and deployment integrations without fixed
  Rembrane environment-variable names.
- A consumed, non-serializable Memory Provider HTTP configuration API for
  applications that resolve endpoint and bearer credentials through their own
  keychains, vaults, cloud secret managers, or deployment systems.
- Zeroization of portable Memory Provider bearer credentials across explicit
  configuration, validation failures, transport construction, and client
  teardown.
- Zeroization of customer key-provider bearer credentials before endpoint
  validation and throughout explicit configuration and transport lifecycles.
- Fail-closed Memory Provider CLI privacy negotiation that requires
  end-to-end encryption by default and accepts weaker provider modes only
  through an explicit operator flag.
- A versioned Graphiti sidecar protocol that derives opaque provider
  namespaces exclusively from canonical workspace identity, requires
  idempotency keys for mutations, bounds transport payloads, and rejects
  mismatched responses.
- A transport-injected Graphiti provider adapter with canonical node and edge
  projection, temporal neighbourhood lookup, version-bounded deletion,
  provider capability negotiation, and shared cross-workspace conformance
  coverage.
- An authenticated Graphiti HTTP transport with fixed versioned operations,
  HTTPS-or-loopback origin validation, header-safe credentials, strict
  timeouts, disabled redirects and proxies, bounded JSON bodies, fail-closed
  manifests, and correlated sidecar responses.
- Portable encoding for arbitrary canonical graph identifiers before they
  enter Graphiti mutation idempotency keys.
- A dependency-free Graphiti sidecar contract core and test gate covering
  deterministic tenant-scoped physical identifiers, cross-workspace endpoint
  denial, idempotent retries, same-version conflicts, temporal traversal, and
  version-bounded deletion.
- A fixed-route FastAPI shell for the Graphiti sidecar with fail-closed bearer
  authentication, constant-time credential comparison, streaming request-size
  enforcement, disabled schema surfaces, and mandatory production-store
  initialization.
- A Graphiti/Neo4j sidecar store that maps exact canonical projections to
  deterministic tenant-scoped entity UUIDs, preserves versions and temporal
  metadata in strict codecs, verifies endpoint tenancy before edge writes, and
  sources graph and model credentials only from the sidecar environment.
- An optional hardened Compose deployment for an unprivileged loopback
  Graphiti sidecar and private persistent Neo4j service, plus an operator guide
  documenting its plaintext-processing trust boundary and secret ownership.
- A cross-language Graphiti boundary gate that starts an explicitly enabled
  in-memory FastAPI sidecar and runs the Rust HTTP provider through the shared
  workspace-isolation, temporal, and deletion conformance suite in dedicated
  CI.
- A configured graph-provider adapter selecting the dependency-free native
  provider or authenticated Graphiti transport from environment-owned
  credentials, with explicit opt-in required for sidecar plaintext processing.
- A dedicated graph projection worker executable that opens the encrypted
  canonical SQLite store, selects the configured provider, drains only that
  provider's durable jobs, and applies bounded retry and polling policy.
- Graph-worker packaging in the main image and Graphiti Compose overlay,
  sharing only the encrypted canonical volume while connecting to the
  authenticated sidecar over the private container network.
- A process-level graph-worker lifecycle test that seeds a canonical encrypted
  SQLite node and provider outbox job through the atomic repository, launches
  the real worker binary, and verifies the auditable job reaches completion.
- An authenticated Memory Provider HTTP discovery client with HTTPS-or-exact-
  loopback enforcement, disabled redirects and environment proxies, bounded
  JSON responses, zeroized bearer credentials, and fail-closed validation of
  every advertised capability, OAuth scope, method, and path binding.
- A typed Memory Provider context-resolution client that excludes connection
  identity from payloads, preserves global/domain/entity/activity selectors,
  validates correlated success and error envelopes, reconstructs canonical
  provenance and disclosure constraints, and reapplies originating item and
  byte limits before returning context.
- Typed Memory Provider proposal writes carrying bounded content, selector,
  idempotency, evidence source, source reference, and observation time while
  excluding workspace, subject, and caller-asserted confirmation fields.
- Exact-version Memory Provider deletion with safe one-segment URL encoding,
  path/payload identity binding, idempotency, correlated errors, and validation
  that the returned tombstone immediately follows the deleted revision.
- Exact-revision Memory Provider explanations over authenticated GET requests,
  with safe path encoding, path/payload/result identity binding, and canonical
  bounded evidence references that exclude raw sources and provider-internal
  reasoning.
- Typed Memory Provider question resolution with scoped queries, caller-bound
  answer and support ceilings, exact supporting memory revisions, and
  context-pack plus disclosure receipt identity.
- Typed Memory Provider event ingestion with idempotent bounded batches,
  scoped opaque event data, server-derived tenant and actor authority, and
  exact-cardinality strictly ordered canonical event results.
- Typed Memory Provider activity checkpoints with safely encoded activity
  paths, idempotent create and optimistic-update shapes, resumable goal and
  work state, and fail-closed consecutive result-version validation.
- Typed Memory Provider disclosure receipt writes with idempotency,
  purpose-bound exact revisions, caller-independent authenticated identity,
  bounded timestamps, and canonical append-only receipt IDs.
- Typed Memory Provider sync pull with opaque cursors, caller-selected page
  bounds, strict resource and operation codecs, payload/digest consistency,
  ordered unique changes, and validated continuation state.
- Typed Memory Provider sync push with an idempotent atomic batch, optimistic
  expected revisions, base-cursor fork detection, ciphertext-compatible
  payload integrity, and ordered one-for-one canonical acknowledgements.
- Canonical Memory Provider HTTPS framing across every operation: direct
  OpenAPI payloads and results, mandatory request/protocol correlation
  headers, query-encoded GET parameters, closed direct error bodies, and
  credential-free public discovery.
- Socket-level Memory Provider client integration tests that inspect direct
  request bodies, bearer and correlation headers, percent-encoded resource
  paths, query parameters, bodyless GET requests, and correlated responses.
- Dedicated Memory Provider CI execution of the independent black-box mock
  conformance proof before dependency-enabled Rust client tests and clippy,
  with a bounded job timeout.
- A configured Memory Provider adapter that discovers and negotiates the
  portable HTTP provider from deployment-owned environment values, retains
  credentials only inside the zeroizing transport, and generates safe
  non-tenant request identity prefixes.
- A typed configured-provider facade for context, questions, proposals,
  events, checkpoints, disclosures, lifecycle, and sync that always creates
  each request through the negotiated capability boundary before transport.
- A self-hosting guide for portable Memory Provider configuration, secret
  injection, fail-closed policy negotiation, provider obligations, and
  cross-tenant black-box conformance testing.
- An object-safe transport-neutral Memory Provider client trait spanning all
  typed operations, implemented by the authenticated HTTP adapter and exposed
  by configured composition for future MCP, local, and community transports.
- Provider-agnostic configured composition that negotiates discovery and
  policy through the common client boundary and owns any boxed transport
  implementation without application changes.
- Unified configured and negotiated request-prefix validation at 8–64
  URL-safe characters, preventing configuration accepted by one layer from
  failing later during connection creation.
- A content-free `rembrane memory-provider check` command that validates the
  complete portable discovery and capability surface and prints only safe
  negotiated provider metadata, privacy mode, domains, and limits.
- Canonical engine-neutral temporal knowledge graph aggregates with typed
  nodes, validated relationship types, strict workspace namespaces, separate
  validity and ingestion time, evidence provenance, bounded aliases, versions,
  and explicit edge supersession references.
- Tenant-isolated knowledge graph repository ports and an in-memory reference
  implementation with bounded temporal neighbourhood traversal, endpoint and
  supersession validation, and optimistic node/edge replacement.
- SQLite schema migration for encrypted temporal graph aggregates, including
  workspace-bound endpoint and supersession foreign keys plus indexed incoming
  and outgoing validity-window traversal.
- Versioned knowledge-node and knowledge-edge codecs plus distinct encryption
  purposes, keeping labels, aliases, relations, and evidence inside
  authenticated ciphertext.
- Encrypted SQLite knowledge graph repository with optimistic replacement,
  ciphertext/metadata binding checks, tenant-scoped temporal traversal, and
  validated supersession lineage.
- Engine-neutral temporal graph provider contract and conformance harness
  covering workspace isolation, validity windows, bounded candidates, and
  deletion semantics.
- Dependency-free native temporal graph provider for local operation,
  deterministic benchmarks, and shared adapter conformance testing.
- Durable graph projection job aggregate with node/edge resource identity,
  provider routing, version bounds, retry accounting, completion, and
  quarantine transitions.
- Graph projection outbox port and tenant-scoped in-memory reference adapter
  with idempotency tuples and optimistic state transitions.
- SQLite graph projection outbox schema with mutually exclusive node/edge
  identities, tenant-bound foreign keys, idempotency tuples, and indexed
  provider polling.
- Resource-specific SQLite partial unique indexes that preserve graph
  projection idempotency despite nullable node/edge identity columns.
- SQLite graph projection outbox repository with provider-scoped polling,
  tenant-bound lookups, strict row decoding, and optimistic status/attempt
  transitions.
- Static SQLite evidence for graph-outbox optimistic claims and cross-workspace
  lookup denial.
- Graph projection worker that re-reads exact canonical node/edge versions,
  skips stale jobs, and applies retry, quarantine, and completion transitions
  to replaceable providers.
- Atomic canonical graph mutation port requiring node/edge persistence and all
  corresponding provider projection jobs to share one transaction boundary.
- In-memory atomic graph mutation implementation with projection identity,
  state, version, and idempotency preflight checks before canonical writes.
- SQLite atomic graph mutation implementation that seals canonical aggregates,
  validates exact projection batches, and commits graph records plus outbox
  work in one transaction.
- Authenticated key-provider HTTP adapter using Rustls, bounded response reads,
  disabled redirects and environment proxies, zeroized bearer credentials,
  strict JSON/base64 decoding, and HTTPS except for exact loopback origins.
- Provider-agnostic configured record cipher selecting environment, macOS
  Keychain, or policy-negotiated HTTP key providers through secret-bearing
  environment variables local to the deployment.
- Dedicated Rust 1.88 test and Clippy CI gate for the key-provider HTTP
  adapter, configured cipher, and CLI, REST, and MCP consumers.
- Strict language-neutral Memory Provider lifecycle fixtures defining actor
  scope expectations and disposable scenario inputs, consumed directly by the
  black-box HTTP conformance client without storing credentials or tenant IDs.
- Portable Memory Provider conformance result schema and runner output pinning
  the tested provider build, fixture corpus, namespace, and every passed
  behavioral profile case.
- Fail-closed Memory Provider negotiation policy covering protocol version,
  required transport and capabilities, explicitly allowed privacy modes, and
  minimum context, event, and sync limits.
- Negotiated Memory Provider connections that generate unique typed request
  envelopes and reject operations absent from the accepted discovery manifest.
- Memory Provider response-correlation validation that rejects mismatched
  request IDs or protocol versions before a typed response body is consumed.
- Complete fail-closed policy rejection coverage for missing transports,
  capabilities, insufficient limits, and malformed policy requirements.
- Sealed Rust Memory Provider payload-to-operation mappings and an
  operation-derived request constructor, preventing downstream callers from
  pairing valid payload types with unrelated privileged operations.
- Compile-time Memory Provider payload-to-result associations with
  request-owned success and error constructors, preventing valid but unrelated
  result objects from being returned for the wrong operation.
- Initial Memory Provider Protocol JSON Schema with strict discovery,
  operation/capability/scope enums, portable and opaque identifiers, sealed
  context selectors, provider limits, and closed request, success, and error
  envelopes, plus a complete ten-operation discovery example enforced by the
  offline protocol gate.
- Strict Memory Provider JSON schemas for context resolution, grounded
  questions, exact-version deletion, and provenance explanation, including
  evidence, sensitivity, disclosure constraints, and executable context
  request/response examples.
- Strict Memory Provider JSON schemas for bounded event batches, unconfirmed
  evidence-bearing proposals, create/update activity checkpoints, and
  append-only disclosure receipts, including a proposal example proving
  workspace, subject, and confirmation authority are absent from client data.
- Strict Memory Provider sync schemas with opaque bounded cursors, closed
  resource and operation enums, distinct server-ordered pull changes and
  sequence-free optimistic push mutations, atomic batch semantics, bounded
  ciphertext payloads, and lowercase SHA-256 integrity digests.
- Complete Memory Provider HTTPS OpenAPI 3.1 binding covering discovery and all
  ten operations with exact OAuth scopes, correlation/version headers,
  operation-specific JSON schemas, closed errors, authenticated identity
  derivation, GET query mappings, and path/body identity equality rules.
- Versioned machine-readable Memory Provider core conformance profile covering
  public discovery, missing and insufficient credentials, proposal
  idempotency, cross-workspace isolation, optimistic deletion conflicts,
  content removal, and workspace-scoped strictly ordered synchronization.
- Secret-safe black-box Memory Provider HTTPS conformance client using three
  distinct scoped connections to verify public discovery, 401/403 separation,
  proposal idempotency, cross-workspace non-disclosure, stale-version
  conflicts, exact tombstones, content removal, and isolated ordered sync,
  with loopback-only plaintext and deterministic fixture cleanup.
- Independent dependency-free local Memory Provider HTTP mock designed to
  execute the black-box conformance client across separate workspace and
  permission identities, verify fixture cleanup, and assert bearer credentials
  never appear in runner output, with opt-in loopback execution in CI.
- Initial full Memory Provider Protocol discovery contract with a versioned
  well-known manifest, HTTPS/MCP transports, portable memory capabilities,
  explicit privacy modes, supported domains, and bounded operation limits.
- Closed Memory Provider Protocol operation registry mapping every portable
  action to one advertised capability, narrow OAuth scope, HTTP method, and
  stable path template.
- Transport-neutral Memory Provider Protocol request and response envelopes
  with bounded correlation IDs, version compatibility checks, explicit
  operation binding, and closed non-enumerating error codes.
- Bounded provider-independent context-resolution request payloads with
  validated purpose/query text, portable global/domain/entity/activity
  selectors, and provider-negotiated item and byte limits.
- Encapsulated Memory Provider context selectors so invalid domain, entity, or
  activity values cannot bypass validated constructors.
- Provenance-bearing Memory Provider context responses with exact canonical
  versions, scope, kind, confidence, validity, sensitivity, disclosure
  constraints, receipt IDs, duplicate rejection, and whole-pack byte limits.
- Idempotent Memory Provider proposal payloads with validated scope, bounded
  content and source references, provenance class, non-future observation
  time, and canonical proposed-record identity—without a client-controlled
  confirmed-status field.
- Bounded Memory Provider activity-checkpoint payloads with separate create and
  optimistic-update shapes, idempotency keys, entity linkage, resumable
  fingerprints, and canonical checkpoint result identities.
- Idempotent append-only Memory Provider disclosure receipt payloads with
  bounded purpose, context-pack linkage, exact unique memory revisions,
  non-future timestamps, and no caller-controlled workspace, subject, or
  client identity fields.
- Exact-version Memory Provider deletion payloads with optimistic concurrency,
  idempotent tombstone creation, bounded audit reasons, and consecutive
  revision validation, plus bounded explanation payloads tied to unique
  immutable evidence references without exposing provider-internal reasoning.
- Idempotent Memory Provider event-batch payloads with validated portable event
  types, sealed scopes, bounded opaque data and provenance references,
  non-future observation times, provider-negotiated item limits, and unique
  canonical event IDs with strictly increasing ledger sequences.
- Bounded Memory Provider question payloads with sealed memory scope and
  provider-negotiated output ceilings, plus answers grounded in unique exact
  memory revisions and linked to canonical context-pack and disclosure receipt
  identities.
- Cursor-bound Memory Provider synchronization payloads with negotiated item
  limits, canonical batch byte ceilings, strictly ordered server pull changes,
  optimistic atomic push mutations, exact request-result correlation, and
  ciphertext-compatible SHA-256 content digests without caller-controlled
  workspace identity or canonical event sequences.
- Expiry-aware remote MCP session capacity reclamation so abandoned bindings
  cannot exhaust the bounded in-process registry indefinitely.
- A transport-neutral remote MCP lifecycle boundary that composes strict HTTP
  request authorization with session establishment, per-request binding
  revalidation, narrow tool scopes, and authenticated session deletion.
- Fail-closed MCP JSON-RPC request classification for the exact tools-only
  server surface, preventing unknown SDK methods or malformed method/tool
  combinations from inheriting generic connection authority.
- Typed remote HTTP authorization outcomes for correct OAuth bearer responses:
  invalid credentials remain `401 Unauthorized`, while authenticated origin,
  tool, and scope denials become `403 Forbidden` without weakening the
  application's non-enumerating `AccessDenied` boundary.
- Hardened remote MCP profile validation against control-character, whitespace,
  quote, non-ASCII, and malformed-authority values before configuration can
  flow into OAuth or MCP HTTP headers.
- Canonical RFC 9728 protected-resource metadata URL and OAuth bearer challenge
  generation from validated, immutable remote MCP resource profiles.
- Pre-alpha remote Streamable HTTP MCP security contract with RFC 9728
  protected-resource metadata, explicit OAuth scope ceilings, bearer challenge
  behavior, verified identity requirements, and per-request session
  reauthentication rules.
- Transport-independent remote token claims validation for exact issuer,
  resource audience, time validity, canonical subject/client/workspace binding,
  and operation-specific OAuth scope ceilings.
- Pluggable remote token-verifier port and non-enumerating authentication
  service that accepts only verifier-produced claims and returns
  connection-bound identity after all semantic checks pass.
- Exhaustive remote MCP tool-to-OAuth-scope mapping, including separate
  checkpoint read/write authority and fail-closed handling for unknown tools.
- Transport-neutral remote HTTP authorization middleware with strict
  case-insensitive Bearer parsing, exact browser-origin allowlisting,
  fail-closed tool lookup, and token verification on every tool request.
- RFC 7662 OAuth introspection adapter with an infrastructure-neutral
  authenticated transport port, strict active/identity/audience/expiry
  requirements, and narrow Rembrane scope conversion.
- Concrete bounded HTTPS introspection transport using authenticated resource
  server credentials, rustls, disabled redirects, strict timeouts, and
  response-size rejection.
- Introspection responses are now stream-bounded independently of
  `Content-Length`, preventing an unbounded body when an authorization server
  omits or falsifies the header.
- Typed remote MCP deployment profiles reject plaintext, partial,
  credential-bearing, or wildcard-origin OAuth configuration before startup
  while retaining the introspection secret only as a provider reference.
- Remote MCP protocol requests now authenticate through a scoped connection
  path, allowing initialize, discovery, event-stream, and session deletion
  without incorrectly substituting a tool-specific OAuth permission.
- Remote session bindings now reject issuer, resource, principal, client,
  workspace, or scope substitution on reauthentication and never extend the
  session beyond the shortest verified token expiry.
- Bounded remote session registry with strict URL-safe identifiers,
  duplicate/capacity protection, non-enumerating revalidation, and
  authorization-checked session deletion.
- Hardened Cloudflare Tunnel Compose overlay and operator guide for
  outbound-only self-hosted access without mounting the memory database or
  workspace encryption credentials into the tunnel container.
- Secret-safe Gemini CLI `settings.json` MCP configuration generation alongside
  the existing Codex, Claude Code, and vendor-neutral connection manifests.
- Dedicated `travel` domain authorization for creating new trip entities,
  avoiding pre-grants for identifiers that do not exist while retaining exact
  entity grants for every revision and research capture.
- `rembrane_create_trip` MCP tool with server-assigned opaque identity,
  encrypted atomic persistence, and travel-domain authorization.
- Exact entity authority derived for the creating MCP connection after trip
  creation, plus an end-to-end encrypted trip-to-research capture lifecycle.
- Authenticated `POST /v1/travel/trips` contract and server route with
  travel-domain creation authority and exact entity capability derivation.
- REST/Postman end-to-end coverage for creating an encrypted trip, deriving
  its entity authority, and capturing expiring research against it.
- Exact-trip travel context resolution for cross-agent handoff, with
  deterministic separation of fresh and expired booking observations.
- Append-only exact-version travel disclosure receipts persisted
  transactionally in schema version 8, covering the trip revision and every
  fresh or expired research revision returned.
- Authenticated REST and MCP travel-context retrieval with exact trip scope,
  explicit purpose and as-of time, plus response minimization that excludes
  opaque provider source references.
- REST/Postman and MCP lifecycle coverage for cross-agent travel continuity
  from encrypted trip creation through research capture and audited recall.
- Explicit `travel-source-references` read permission, limited to owner/admin
  connections and requiring per-request opt-in before opaque provider
  references can leave the application boundary.
- Application-level travel disclosure projections that redact sensitive source
  references by default, plus schema version 9 receipts recording whether a
  privileged response included them.
- Narrow optimistic trip-participant mutation over REST and MCP with
  server-assigned participant identity, preventing agents from replacing the
  complete trip aggregate to make one localized change.
- Narrow REST and MCP mutations for evidence-backed trip constraints and
  authenticated trip decisions; decision attribution is server-bound and
  cannot be spoofed through model-controlled arguments.
- Distinct `travel-sensitive-profile` read permission for participant,
  constraint, and decision disclosure, separate from opaque provider
  source-reference authority and requiring explicit per-request intent.
- Application-level safe trip projections prevent REST and MCP adapters from
  bypassing sensitive-profile redaction, with schema version 10 disclosure
  receipts recording every privileged inclusion.
- Explicit trip create/revise permissions, exact entity-scoped authorization,
  versioned trip audit events, and atomic in-memory trip/event mutations.
- Member trip revisions through persisted entity grants while trip creation
  remains restricted to workspace owners and administrators.
- Version 3 canonical event encoding for trip lifecycle events while retaining
  the existing version 1 and version 2 wire formats.
- Schema version 6 encrypted SQLite trip storage with workspace-bound
  ciphertext, optimistic revisions, atomic audit events, and owner-scoped
  listing.
- A distinct `trip-entity` encryption purpose in the record-cipher and external
  key-provider contract to prevent ciphertext substitution across data types.
- Encrypted SQLite trip adapter tests covering duplicate opaque identifiers
  across tenants, owner-scoped reads, atomic sequence-conflict rollback, and
  optimistic revision conflicts.
- Canonical booking-research records tied to trips with evidence provenance,
  bounded opaque source references, strict UTC timestamps, and deterministic
  fresh/expired evaluation.
- Version 1 `rembrane.booking-research` wire encoding with strict domain
  reconstruction and provider-independent evidence representation.
- Explicit booking-research capture permission, exact trip-scope enforcement,
  versioned audit events, and atomic in-memory capture with sequence-conflict
  rollback.
- Schema version 7 encrypted booking-research storage bound to canonical trips,
  with a distinct encryption purpose, tenant-scoped reads, and atomic event
  persistence.
- Authenticated `POST /v1/travel/booking-research` API contract and server
  handler with connection-grant enforcement, strict research validation, and
  conflict-aware responses.
- `rembrane_capture_booking_research` MCP tool with server-assigned canonical
  identifiers, exact trip grants, evidence attribution, and expiry validation.
- REST/Postman and MCP end-to-end assertions that discover the capture surface
  and reject research for a missing canonical trip without appending an event.
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

- REST API and MCP startup now honor `REMBRANE_KEY_PROVIDER` through the same
  keyring loader as the CLI, so macOS Keychain selection and historical-key
  reads are no longer silently bypassed.
- CLI, REST, and MCP storage now use the provider-agnostic configured cipher;
  generated agent configs and privacy diagnostics recognize authenticated
  HTTP key providers without embedding bearer credentials.
- Extracted the canonical MCP tool implementation into a reusable Rust library
  so stdio and remote Streamable HTTP transports share one handler surface.
- Added verified-remote-access initialization for the shared MCP handler;
  remote subject, client, and workspace identity no longer need to come from
  process-level identity environment variables.
- Cross-tenant remote-access integration coverage proving OAuth claims cannot
  bypass canonical workspace membership and that wrong-audience, expired, and
  invalid tokens fail closed.
- Opt-in `/.well-known/oauth-protected-resource/mcp` endpoint with exact HTTPS
  resource and authorization-server configuration and the supported narrow
  Rembrane OAuth scopes.
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

- Key-provider request correlation now fails permanently at atomic sequence
  exhaustion instead of wrapping and risking identifier reuse.
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
