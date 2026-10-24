# Changelog

All notable changes to Rembrane will be documented in this file.

The project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and intends to use semantic versioning after the initial protocol stabilizes.

## [Unreleased]

### Added

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
