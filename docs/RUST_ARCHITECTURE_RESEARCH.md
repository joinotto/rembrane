# Rust Architecture Research

## Central Memory Framework

**Status:** Architecture recommendation  
**Research snapshot:** 23 October 2026  
**Related document:** `PRODUCT_REQUIREMENTS_AND_ARCHITECTURE.md`

---

## 1. Decision summary

Rust should be the primary implementation language for the open-source memory core, CLI, local daemon, synchronization engine, authorization layer, E2EE implementation, background workers, and self-hosted API.

The web dashboard should remain TypeScript/React. Existing Python memory systems such as Mem0 and Graphiti should run as replaceable sidecars accessed through versioned provider protocols.

Recommended language boundary:

```text
Rust
├── canonical domain model
├── API and MCP server
├── setup CLI
├── local/E2EE gateway
├── synchronization
├── workspace authorization
├── provider orchestration
├── event and job processing
├── context compiler
└── native semantic/search adapters

Python sidecars
├── Mem0
├── Graphiti
├── Cognee
└── model-specific experimental pipelines

TypeScript
├── web dashboard
├── browser extension
├── JavaScript SDK
├── Tauri desktop UI
└── thin Cloudflare edge gateway
```

This is preferable to forcing every component into Rust or retaining TypeScript as the authoritative server implementation.

---

## 2. Why Rust fits this product

The platform handles long-lived private data, encryption keys, concurrent writes, tenant boundaries, background processing, local databases, and portable binaries. Rust provides strong compile-time ownership and concurrency guarantees, predictable native performance, and a mature ecosystem for these requirements.

Rust is especially valuable for:

- Secret and key handling.
- A single portable CLI and local daemon.
- Memory-safe parsing of untrusted events and provider responses.
- High-throughput ingestion and context retrieval.
- Explicit error handling around deletion, synchronization, and authorization.
- Sharing one domain model between server, CLI, worker, and desktop gateway.
- Running local search without a heavyweight language runtime.

Rust does not eliminate logical security failures. Cross-tenant leakage, incorrect authorization, weak key recovery, and memory poisoning remain application-design problems.

---

## 3. Relevant open-source Rust systems

### 3.1 Tokio, Axum, and Tower

Use Tokio as the async runtime, Axum for HTTP routing and extraction, and Tower for middleware such as authentication, authorization, rate limiting, tracing, timeouts, and concurrency limits.

Axum is designed around Tokio, Hyper, and Tower rather than introducing a separate middleware abstraction. [Axum repository](https://github.com/tokio-rs/axum) and [Tokio Axum introduction](https://tokio.rs/blog/2021-07-announcing-axum).

Architectural lesson:

```text
Transport
  → Tower middleware
  → request context
  → application use case
  → domain ports
  → provider adapters
```

HTTP handlers must remain thin. They should authenticate, validate, invoke one application use case, and serialize the result.

### 3.2 Official MCP Rust SDK

The official MCP Rust SDK uses Tokio and supports MCP server implementation. It should power the native stdio and remote HTTP MCP surfaces instead of maintaining a separate TypeScript MCP server. [Official MCP Rust SDK](https://github.com/modelcontextprotocol/rust-sdk).

REST and MCP should call the same application services:

```text
REST adapter ─┐
MCP adapter  ─┼─→ Application services → Domain ports
CLI adapter  ─┘
```

### 3.3 SQLx

Use SQLx for PostgreSQL rather than a full ORM. SQLx supports asynchronous PostgreSQL and SQLite access, migrations, prepared statements, and optional compile-time query checking. Its offline mode permits checked query metadata to be committed for CI builds without a live database. [SQLx repository](https://github.com/transact-rs/sqlx) and [SQLx documentation](https://docs.rs/crate/sqlx/latest).

Reasons:

- The product needs explicit SQL for PostgreSQL RLS, recursive graph queries, temporal queries, and locking.
- Database behaviour should not be hidden behind an ORM.
- Compile-time checked SQL can catch schema/query drift.
- Repository traits keep SQLx out of domain code.

### 3.4 Qdrant

Qdrant is a useful architectural reference and optional provider because it is a Rust vector engine with collections, shards, segments, write-ahead logging, payload filtering, snapshots, and tenant-oriented sharding. [Qdrant overview](https://qdrant.tech/documentation/overview/), [storage design](https://qdrant.tech/documentation/manage-data/storage/), and [multitenancy](https://qdrant.tech/documentation/tutorials/multiple-partitions/).

Architectural lessons:

- Acknowledged writes need durable ordering.
- Storage mutation and index optimization should be separate paths.
- Indexes are replaceable projections, not canonical truth.
- Tenant filtering must participate in physical/index design.
- Snapshot and restoration are product features, not operational afterthoughts.

Qdrant can be supported as a vector provider. PostgreSQL with pgvector should remain the simplest reference deployment.

### 3.5 Tantivy

Tantivy is a Lucene-inspired full-text search library written in Rust. It is appropriate for the local/E2EE gateway, where plaintext indexes must remain on the authorized device. [Tantivy repository](https://github.com/quickwit-oss/tantivy) and [architecture](https://github.com/quickwit-oss/tantivy/blob/main/ARCHITECTURE.md).

Use cases:

- Local exact and fuzzy memory search.
- Artifact and work-trace indexing.
- Searchable strict-E2EE deployments.

Hosted PostgreSQL full-text search remains sufficient for the first managed deployment.

### 3.6 Cedar

Cedar is an open-source authorization language and Rust evaluation engine designed for fine-grained RBAC/ABAC decisions. It separates policies from application code and evaluates requests over principals, actions, resources, and contextual entities. [Cedar repository](https://github.com/cedar-policy/cedar), [authorization guide](https://docs.cedarpolicy.com/auth/authorization.html).

Use Cedar for application authorization:

```text
Principal: user, member, device, or AI client
Action: read memory, propose, confirm, export, checkpoint
Resource: workspace, domain, entity, activity, or memory
Context: purpose, sensitivity, device trust, authentication level
```

PostgreSQL RLS remains a second database-level isolation boundary. Cedar does not replace RLS.

### 3.7 OpenMLS

OpenMLS is a Rust implementation of Messaging Layer Security as standardized by RFC 9420. Use it for membership changes and shared-workspace key epochs rather than inventing a group-key protocol. [OpenMLS repository](https://github.com/openmls/openmls).

MLS should distribute and rotate workspace keys. Individual memory records and artifacts should use independently versioned content keys.

### 3.8 Rust cryptographic libraries

Avoid deprecated `sodiumoxide`. RustSec records it as deprecated. [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2021-0137.html).

Shortlist two implementation approaches for a security review:

1. Maintained low-level bindings through `libsodium-sys-stable`, wrapped by a very small audited safe API.
2. `dryoc`, a pure-Rust libsodium/NaCl-compatible library with protected-memory facilities.

Sources: [libsodium-sys-stable](https://github.com/jedisct1/libsodium-sys-stable) and [dryoc](https://github.com/brndnmtthws/dryoc).

Do not finalize the cryptographic binding until:

- Required algorithms are mapped.
- Mobile, desktop, WebAssembly, and server targets are tested.
- Constant-time and protected-memory behaviour is reviewed.
- An independent security review is planned.

Use `secrecy` and `zeroize` for reducing accidental secret exposure and clearing supported values on drop. They do not guarantee that every historical copy has disappeared from process memory. [secrecy](https://docs.rs/secrecy/latest/secrecy/) and [zeroize](https://docs.rs/zeroize/latest/zeroize/).

### 3.9 SQLCipher and Rusqlite

Use Rusqlite with its bundled SQLCipher feature for the local encrypted database. Rusqlite can compile and link SQLCipher through supported feature flags. [Rusqlite repository](https://github.com/rusqlite/rusqlite).

SQLx remains the server PostgreSQL library. Rusqlite is preferable for the local gateway because SQLCipher configuration and synchronous embedded access can be contained behind a dedicated storage actor.

### 3.10 Rustls

Use Rustls for native-server TLS where TLS is terminated by the application. Rustls implements TLS protocol processing in memory-safe Rust. [Rustls](https://rustls.dev/).

Production deployments may still terminate TLS at Cloudflare, a reverse proxy, or a cloud load balancer.

### 3.11 Wasmtime and the Component Model

Wasmtime supports WebAssembly, WASI, and the Component Model for portable cross-language components. [Wasmtime documentation](https://docs.wasmtime.dev/).

It is a good future foundation for sandboxed third-party provider plugins, but it should not block the first release. Start with:

1. In-tree Rust providers.
2. Versioned HTTP/gRPC external providers.
3. WebAssembly component plugins after provider contracts stabilize.

Never load untrusted native dynamic libraries into the core process.

### 3.12 Cloudflare Rust support

Cloudflare supports Rust Workers through `workers-rs`, compiled to WebAssembly, with bindings for products including R2 and Queues. [Cloudflare Rust support](https://developers.cloudflare.com/workers/languages/rust/).

However, Rust Worker dependencies must support the Worker WebAssembly target; arbitrary native Rust crates cannot be assumed to work. [workers-rs repository](https://github.com/cloudflare/workers-rs).

Recommendation:

- Keep the portable core as a native Rust service.
- Initially use a thin TypeScript Cloudflare Worker for edge authentication, routing, WAF-adjacent logic, and Durable Object coordination.
- Add a Rust edge build only after its dependency graph and operational benefits justify the additional target.

Cloudflare must remain optional. Self-hosters should run the native Rust binary or container directly.

### 3.13 Tauri desktop application

Use Tauri for the non-technical local installation experience. Tauri combines a Rust application core with a webview-based frontend and supports tray applications and signed updates. [Tauri architecture](https://tauri.app/concept/architecture/) and [updater](https://tauri.app/plugin/updater/).

The desktop shell should:

- Install and supervise `memory-local`.
- Manage onboarding, provider selection, connection cards, capture state, and recovery.
- Open OS-native consent and file-selection flows.
- Expose only narrow typed commands from the webview to Rust.
- Keep decrypted memories and raw keys out of frontend JavaScript state.
- Offer advanced configuration without requiring it.

Tauri Stronghold may be evaluated as one secret-storage adapter, but OS keychains remain the preferred default and the platform cryptographic design must not depend exclusively on a Tauri plugin. [Tauri Stronghold](https://tauri.app/plugin/stronghold/).

---

## 4. Recommended architecture style

Use a modular monolith with hexagonal boundaries.

```text
Domain
├── entities and value objects
├── invariants
├── memory lifecycle
├── authority and scope
└── no networking/database dependencies

Application
├── commands
├── queries
├── orchestration
├── transactions
└── domain ports

Adapters
├── PostgreSQL
├── SQLite/SQLCipher
├── Graphiti
├── Mem0/Hindsight/Cognee
├── vector stores
├── object stores
├── REST
├── MCP
└── CLI
```

Avoid starting with microservices. Separate executables may share the same core crates:

```text
memory-server
memory-worker
memory-cli
memory-local
```

They can be deployed independently without splitting domain ownership across repositories or protocols.

---

## 5. Proposed Rust workspace

```text
central-memory/
├── Cargo.toml
├── crates/
│   ├── memory-domain
│   ├── memory-application
│   ├── memory-contracts
│   ├── memory-crypto
│   ├── memory-authz
│   ├── memory-config
│   ├── memory-sync
│   ├── memory-context
│   ├── memory-observability
│   ├── memory-provider-sdk
│   ├── adapter-postgres
│   ├── adapter-sqlite
│   ├── adapter-graphiti
│   ├── adapter-mem0
│   ├── adapter-hindsight
│   ├── adapter-qdrant
│   ├── adapter-pgvector
│   ├── adapter-r2
│   └── adapter-s3
├── apps/
│   ├── memory-server
│   ├── memory-worker
│   ├── memory-cli
│   └── memory-local
├── web/
│   └── dashboard
├── integrations/
│   ├── browser-extension
│   └── javascript-sdk
├── services/
│   ├── graphiti-sidecar
│   └── memory-engine-sidecar
└── deploy/
```

Dependency direction:

```text
domain ← application ← adapters/apps
```

The domain crate must not depend on Axum, SQLx, Graphiti, Mem0, Cloudflare, or provider SDKs.

---

## 6. Core crate recommendations

| Concern | Recommended component |
|---|---|
| Async runtime | Tokio |
| HTTP API | Axum |
| Middleware | Tower / tower-http |
| MCP | Official `rmcp` SDK |
| PostgreSQL | SQLx |
| Local SQLite | Rusqlite + SQLCipher |
| Desktop application | Tauri with a narrow Rust command surface |
| Serialization | Serde |
| CLI | Clap derive |
| Configuration | Figment or `config`, selected by prototype |
| Errors | Typed domain errors; `thiserror` internally |
| Diagnostics | `tracing` + OpenTelemetry |
| Authorization | Cedar |
| OIDC client/resource verification | `openidconnect` plus reviewed JWT validation |
| HTTP providers | Reqwest + Rustls |
| E2EE groups | OpenMLS |
| Secret wrappers | secrecy + zeroize |
| Local full-text | Tantivy |
| Vector | pgvector default; Qdrant optional |
| Plugin sandbox later | Wasmtime Component Model |

Clap provides derive-based CLI definitions. [Clap documentation](https://docs.rs/clap/latest/clap/). Figment can combine hierarchical configuration sources and retain source metadata. [Figment repository](https://github.com/SergioBenitez/Figment).

Use `tracing` as the internal structured instrumentation API and export sanitized telemetry through OpenTelemetry. [OpenTelemetry Rust](https://opentelemetry.io/docs/languages/rust/).

---

## 7. Provider interoperability

Provider traits should be language-neutral at the process boundary.

### In-process Rust providers

Use Rust traits for low-overhead stable components:

```rust
#[async_trait]
pub trait VectorStore: Send + Sync {
    async fn upsert(&self, request: VectorUpsert) -> Result<(), ProviderError>;
    async fn search(&self, query: VectorQuery) -> Result<Vec<VectorHit>, ProviderError>;
    async fn delete_scope(&self, scope: DeleteScope) -> Result<(), ProviderError>;
    async fn health(&self) -> Result<ProviderHealth, ProviderError>;
}
```

### External providers

Mem0, Graphiti, and Cognee should use a versioned protocol:

```text
Rust core
  → authenticated HTTP/gRPC
  → provider sidecar
  → provider library
```

Requirements:

- Capability discovery.
- Timeouts and circuit breakers.
- Idempotency keys.
- Workspace namespace supplied by the core.
- No provider-controlled authorization decision.
- Version negotiation.
- Health and readiness.
- Export and deletion verification.

The sidecar receives only the minimum data required for its job.

---

## 8. Data consistency

PostgreSQL remains canonical. Graph, vector, full-text, and compiled-context stores are projections.

Write sequence:

```text
1. Validate request and authorize.
2. Begin PostgreSQL transaction.
3. Append immutable event.
4. Apply authoritative state transition.
5. Insert outbox records.
6. Commit.
7. Worker projects to graph/vector/search.
```

Workers use idempotent projection keys:

```text
workspace_id + event_id + projection_type + schema_version
```

Read-after-write operations use PostgreSQL state. Semantic and graph retrieval may be eventually consistent and must report projection versions.

---

## 9. E2EE architecture in Rust

The Rust local daemon is the trusted endpoint:

```text
AI tool
  → local MCP/HTTP
  → Rust daemon
  → decrypt and authorize
  → local exact/vector/graph retrieval
  → minimal context response
```

The cloud receives:

- Ciphertext records.
- Wrapped keys.
- Opaque workspace/device identifiers.
- Synchronization sequence metadata.
- Minimal routing metadata.

Strict-E2EE mode cannot use hosted Mem0, Graphiti, Vectorize, or plaintext PostgreSQL indexing. Those engines must run locally or in a customer-controlled trusted gateway.

Cryptography remains isolated in `memory-crypto`; no other crate manipulates raw key bytes.

---

## 10. Configuration and secrets

Typed configuration is loaded once at startup:

```text
CLI overrides
> secret references
> environment variables
> config file
> safe defaults
```

Secret values use `SecretString` or domain-specific secret types and must not implement unrestricted `Debug`, `Display`, or serialization.

Provider configuration is separated into:

```text
public settings
credential references
resolved runtime secrets
capability report
```

The CLI can test credentials without writing them to disk.

### Credential-custody guarantee

For local, Mac mini, on-premises, and customer-cloud deployments:

```text
User environment
├── owns database credentials
├── owns Graphiti/Neo4j credentials
├── owns Mem0/Hindsight/Cognee credentials
├── owns model and embedding credentials
├── owns object-storage credentials
└── connects directly to those providers

Framework maintainers/hosted control plane
└── receive none of those credentials
```

The Rust core resolves secrets only inside the running deployment. Provider adapters receive scoped secret handles or `SecretString` values at initialization; domain code never receives raw credentials.

Supported secret sources:

- macOS Keychain, Windows Credential Manager/DPAPI, and Linux Secret Service.
- Customer cloud secret managers.
- Docker/Kubernetes mounted secrets.
- Protected local secret files.
- Environment variables for portable deployments.

Direct command-line secret values should be rejected or require an explicit unsafe override because they can be retained by shell history or process inspection.

Self-hosted builds must not phone home. Telemetry, update checks, and crash reporting are opt-in. Offline mode must enumerate and block unexpected outbound connections.

---

## 11. Testing strategy

### Unit tests

- Domain invariants
- Scope and authority resolution
- Conflict handling
- Memory lifecycle
- Cryptographic envelope parsing

### Property-based tests

- No invalid lifecycle transitions
- Encryption round trips
- Serialization compatibility
- Policy monotonicity where required
- Sync convergence

### Integration tests

- PostgreSQL RLS
- Graphiti namespace isolation
- Mem0/Hindsight provider contracts
- Outbox replay
- Deletion propagation
- Backup restoration

### Adversarial tests

- Cross-workspace identifiers
- Prompt injection in memories
- Malicious provider responses
- Oversized and malformed events
- Duplicate queue deliveries
- Concurrent checkpoints
- Stale device/member keys

### Compatibility tests

Every provider adapter runs against a shared conformance suite.

---

## 12. Open-source delivery

Release:

- Native binaries for Linux, macOS, and Windows.
- Signed desktop installers for non-technical users.
- Container images.
- Cargo crates for contracts and provider SDKs.
- TypeScript and Python client SDKs generated from stable schemas where practical.
- Docker Compose reference deployment.
- Reproducible migrations.
- Software bill of materials.
- Signed releases and checksums.

The CLI should manage:

```text
memory init
memory doctor
memory migrate
memory server
memory worker
memory connect
memory provider test
memory backup
memory restore
memory export
```

The desktop application invokes the same application services as the CLI rather than duplicating installation or memory logic.

---

## 13. Architectural decisions

### Adopt

- Rust as the portable core and primary backend language.
- Axum/Tokio/Tower for native services.
- SQLx with explicit PostgreSQL queries and RLS.
- Official Rust MCP SDK.
- Cedar plus PostgreSQL RLS for defense-in-depth authorization.
- OpenMLS for shared-workspace membership cryptography.
- Rusqlite/SQLCipher and Tantivy for the local gateway.
- Python sidecars for Graphiti and semantic-memory engines.
- Traits plus versioned external protocols for providers.
- Transactional outbox and asynchronously rebuilt projections.

### Defer

- WebAssembly provider marketplace.
- Rust on Cloudflare’s edge.
- Microservice decomposition.
- Custom vector or graph database.
- Replacing proven Python memory engines with Rust rewrites.

### Reject

- Building cryptographic algorithms.
- Making Graphiti or Mem0 canonical.
- Loading untrusted native plugins.
- Sharing provider SDK types with the domain layer.
- Storing plaintext secrets in configuration.
- Treating approximate indexes as authoritative storage.

---

## 14. Final recommendation

Build a native Rust modular monolith with multiple binaries:

```text
memory-server  → Axum REST + official MCP SDK
memory-worker  → event projections and consolidation
memory-cli     → setup, providers, migration, connection
memory-local   → E2EE local gateway and search
```

Use:

```text
Tokio + Axum + Tower
SQLx + PostgreSQL
Rusqlite + SQLCipher
Cedar + PostgreSQL RLS
OpenMLS
Reviewed libsodium-compatible encryption binding
Tantivy for local text search
pgvector by default; Qdrant as an optional provider
Graphiti and Mem0/Hindsight/Cognee as sidecars
Cloudflare as an optional thin edge and synchronization platform
```

This gives the open-source project a small, secure, portable core while maximizing reuse of existing memory and graph systems. Rust owns the trust boundary and durable orchestration; specialized external engines remain replaceable.
