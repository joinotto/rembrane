# Testing Rembrane

Rembrane is pre-alpha. Test only with disposable data and development keys.

## Prerequisites

- Rust 1.88 with `rustfmt` and `clippy`
- SQLite 3
- Node.js 22
- `jq`
- Postman CLI

Run every check:

```text
./scripts/test-all.sh
```

The local CLI, MCP, REST, and cross-tool lifecycle scripts clear inherited
`REMBRANE_*` settings before creating fixture configuration. Only
`REMBRANE_BIN`, `REMBRANE_API_BIN`, `REMBRANE_MCP_BIN`, and
`REMBRANE_TEST_LISTEN` are retained as explicit test overrides. Fixtures select
the environment key provider with public development keys and the native graph
provider. Inherited key references, historical keyrings, remote-provider
credentials, identity, and permission settings cannot redirect these tests.
The reset does not print values or change the parent shell.

This is configuration isolation, not an OS/network sandbox. Other environment
variables remain inherited, binary overrides must be trusted, and the REST
listen override must name a disposable local test address. Real-provider/KMS
conformance runners deliberately use their explicit configuration and are not
covered by this reset. Node is required even for the standalone CLI fixture.
The static suite checks isolation and that all four lifecycle scripts source
the reset before running binaries.

When Rust or network access is unavailable, run the complete non-Rust
preflight:

```text
./scripts/test-static.sh
```

The suite performs:

1. architecture, sensitive-file, and protocol conformance checks;
2. SQLite schema and transaction tests;
3. Rust formatting, Clippy, unit, and integration tests;
4. complete encrypted CLI lifecycle testing;
5. MCP stdio initialization and tool invocation;
6. CLI-to-fresh-MCP continuity for preferences, approved work traces, and
   working-memory checkpoints, including exact-version disclosure receipts;
7. REST authentication and tenant-isolation checks through Postman.

Run just the local cross-tool handoff after building the binaries:

```sh
cargo build -p rembrane-cli -p rembrane-mcp
./scripts/test-cross-tool-continuity.sh
```

This disposable encrypted scenario proves proposed observations stay out of
confirmed-only recall, approval adds user-statement provenance, and a fresh
agent recalls the confirmed version. Missing approval, wrong scope/key,
foreign tenant routing, stale versions, and repeated confirmation must fail
without modifying canonical memory, evidence, or audit events. The CLI
lifecycle suite additionally rejects confirmation of a deleted observation.

## PostgreSQL fixture safety

```sh
node scripts/test-postgres-fixture-guard.mjs
```

This uses a fake `psql` client to verify fail-closed admission and credential
redaction, and deliberately stops at the first migration. It never proves live
SQL execution, tenant isolation, or PostgreSQL repository behavior.

For the real RLS suite, follow the private libpq service setup in
[Production testing](PRODUCTION_TESTING.md#safe-postgresql-fixture-setup).
It requires a fresh isolated disposable instance, an explicitly named
`rembrane_test_` database, and explicit fixture authorization. Application
database URLs are not test authorization. The runner no longer drops/reset
existing state and leaves test resources for inspection.

## Startup authorization before keys and providers

```sh
cargo test -p rembrane-api -p rembrane-mcp --locked --offline
```

Both services perform canonical membership/rotation checks against metadata
storage before initializing workspace ciphers or graph clients. These checks
do not require record decryption. A rejected principal, workspace mismatch,
suspended member, or removed member never reaches the provider initializer.
MCP denies pending key rotation before provider initialization as well.

REST retains its existing explicit exceptions: an eligible known principal
can start in invitation-only mode, and an active owner/admin can start in
rotation-recovery mode. Those grants have no memory read scopes, read
permissions, write scopes, or write permissions. They are not ordinary memory
access and must not be broadened because startup succeeded.

The application tests use real in-memory SQLite metadata and observable
provider-initialization counters. Authorized fixtures now use the same startup
builders as production, including encrypted remember/recall and exact remote
identity checks. Provider failures still prevent a usable runtime/service.
These tests do not contact a real KMS or graph endpoint.

This is not a promise of zero startup I/O: opening SQLite may initialize or
migrate database metadata, and REST still validates its configured bearer and
discovery settings. Blocking provider construction still belongs outside the
async executor or on the documented bounded initializer workers. Canonical
membership/permissions must still be reauthorized on every operation; startup
authorization is not a reusable grant of permanent authority.

## REST blocking-worker boundary

Run the no-listener REST runtime tests with:

```sh
cargo test -p rembrane-api --locked --offline
```

The REST executable constructs synchronous provider clients before entering its
async runtime. Authenticated canonical handlers move storage, encryption,
graph-provider calls, and their existing mutex acquisition onto blocking
workers. One service state admits at most eight outstanding operations,
including work waiting for the canonical runtime mutex. This is a resource
ceiling, not a claim of eight concurrent SQLite transactions or measured
throughput.

Unauthenticated requests are rejected before worker admission. Saturation
returns HTTP 503 with the closed `service_busy` JSON problem and `Retry-After: 1`;
the canonical operation has not started on that path. Health and discovery
remain lightweight async handlers.

Cancellation **after admission** is different: a synchronous operation may
continue and commit even after the caller stops waiting. Its admission permit
stays with the worker until completion, preventing cancellation from bypassing
the ceiling. Inspect the canonical version or event sequence after a lost
mutation response; do not blindly retry it. Worker failures return the existing
generic internal-error response without forwarding panic details to callers.

Current-thread tests prove off-executor blocking HTTP-client construction,
overload denial without execution, application-error/panic cleanup, capacity
retention after cancellation, responsive health during a blocked worker,
authentication-before-admission, tenant denial, and encrypted remember/recall.
These tests do not replace listener/Postman, real-provider, container,
resource-exhaustion, or load/recovery testing. The eight-job ceiling does not
bound every connection or pre-handler request-body allocation; deployment
limits and staging measurements remain required.

## MCP blocking-worker boundary

Run the no-listener MCP runtime tests with:

```sh
cargo test -p rembrane-mcp --locked --offline
```

All fourteen tools dispatch synchronous provider/storage work and canonical
mutex acquisition onto blocking workers. Production service constructors use
one process-shared eight-operation budget, including async initialization and
workers waiting for storage. This is not a fairness policy, connection limit,
eight parallel SQLite transactions, or a throughput guarantee.

The executable initializes providers before entering the executor. Async
embedders should use `RembraneMcp::from_environment_async` or
`RembraneMcp::from_verified_remote_access_async`, not the synchronous
constructors. Initialized service clones share state and capacity.

Remote-mode tools check immutable per-request verified identity before
admission without locking mutable state. The complete SDK `RequestContext`
then reaches the worker, where current canonical membership, scopes, and
permissions are still reauthorized. A cached connection is not authorization.
Overload rejects without executing the operation and returns a generic MCP
internal error; worker panics do not expose their details in responses.

Cancellation is checked before admission, at worker entry, and again after
storage-lock acquisition before application mutations. Cancellation arriving
after those checks may still leave a committed mutation. Abandoning the
response does not free admission capacity until actual worker completion.
Inspect canonical versions/events before retrying a lost mutation response.

Tests use the actual pinned SDK handshake and JSON-RPC tools over an in-memory
duplex transport. They prove encrypted remember/recall, verified request-proof
preservation, identity denial before admission without locking storage,
off-executor blocking HTTP-client construction, overload/failure cleanup,
capacity retention after abandoned requests, and cancellation while waiting
for storage. No listening socket, uncached SDK client feature, or fake peer
constructor is required.

## Remote OAuth authorization workers

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline
```

The owned and shared authorization-service async entrypoints now use one
process-shared eight-worker authorization budget, separate from MCP tool work.
Initialize, compatibility initialization, stateless calls, event streams,
established-session calls, and deletion all use it. Verification remains fresh
on every request, runs outside the registry lock, and is followed by the
existing exact-body, method/scope, origin, session, and tenant policies.
Owned entrypoints delegate to the shared implementation.

Admission has no wait queue; saturation rejects with HTTP 503 and
`Retry-After: 1` before invoking the verifier or SDK. Panic/join failures return
the same generic rejection. Worker ownership lasts until actual completion,
even if its caller stops waiting. A running provider call is not forcibly
interrupted: transport timeouts remain essential. Scheduling and verification
time advance the trusted request-time snapshot by elapsed monotonic whole
seconds; expired claims and timestamp overflow fail closed. This does not
provide a trusted wall clock if the embedding caller supplies an incorrect one.

The worker-owned authorization header copy is zeroizing and never forwarded
to the downstream SDK. Canonical plaintext body ownership and verified
per-request extensions retain their previous security boundaries.

Tests cover actual async service dispatch, off-executor blocking-client
construction, per-request verification, shared production constructor budgets,
all-route overload with no verifier/SDK invocation, error/panic cleanup,
capacity retention after abandoned verification, and elapsed-expiry checks.
Initialization cancellation tests now wait for actual dispatch notification
instead of assuming one poll crosses worker initialization.

Synchronous service methods and borrowing gate/free-function helpers remain
lower-level compatibility APIs. Their verifier execution is not automatically
offloaded; do not use blocking network clients through them on an executor.
Build blocking provider clients outside the executor and prefer the
owned/shared async service routes when embedding HTTP.

These tests do not establish live Streamable HTTP support, real HTTPS
introspection, cloud-provider conformance, measured load limits, or production
readiness. Actual SDK listener and staging verification remain required.

## Tenant service construction and cache concurrency

The remote adapter test command above also covers the tenant Tower dispatcher.
POST, SDK initialization, compensation, event-stream GET, and session DELETE
select their exact verified tenant service on blocking workers. Production
dispatchers share a separate eight-job factory budget. It includes cache
lookups and threads waiting for the same in-progress constructor; it is not a
fairness guarantee or measured performance target.

Saturated/closed capacity or a panicked worker returns the closed, redacted
`TenantAwareTowerMcpDispatchError::FactoryUnavailable`. Factory errors retain
their existing redacted error boundary. No SDK request starts on those paths.
The concrete HTTP listener must map factory-unavailable failures to its
overload response; this library test does not establish that unwired mapping.

The cache counts ready services plus pending constructions against its
configured capacity. Only one constructor runs for an exact issuer/resource/
subject/client/workspace/scope identity. It runs outside the global cache
mutex; other ready or cold tenants can proceed if capacity remains. Same-key
waiters release that mutex while waiting, then reuse the completed service
and extend retention only from their latest validated expiry.

Failed/panicked constructors release their pending slot and notify waiters;
an ordinary constructor panic no longer poisons the global cache mutex. A
poisoned cache still fails closed. An abandoned async request cannot free a
running worker slot or permit duplicate construction: initialization may
complete and remain cached until its retention deadline. Provider timeouts
remain necessary because synchronous constructors are not forcibly stopped.

Tests prove actual blocking HTTP-client construction off the executor, exact
verified access preservation, process-shared factory budgets, all five dispatch
paths denying overload before constructor/SDK invocation, panic recovery for
another tenant, cancellation-safe worker/cache ownership, unrelated tenant
progress during blocked construction, ready-plus-pending capacity, and
single-flight construction with refreshed-token retention.

Expiry pruning removes ready entries while locked, then destroys those
services outside the global mutex. Tests prove warm/cold tenant progress
and capacity reuse during blocked cleanup, an unpoisoned cache after cleanup
panics, and preservation of pending constructor reservations during pruning.
Cleanup panics still propagate to the caller; they are not converted into
successful pruning. Active clones may retain a service after cache removal.
Pruning is synchronous and may block in cleanup, so async callers must arrange
blocking execution. These are library tests, not live provider shutdown proof.

Direct synchronous factory/cache methods are lower-level APIs, not automatic
offload boundaries. Embed them through the tenant-aware async dispatcher or
provide caller-managed blocking execution. Real SDK listener integration,
provider startup/shutdown, load/fairness, and recovery drills remain pending.

## Remote proof lifetime and delayed execution

`VerifiedRemoteAccess` carries a private monotonic deadline derived from the
trusted epoch-second validation snapshot. Verification and authorization-worker
time narrow that deadline; narrowing can never renew it or alter token claims.
Clones preserve the deadline. Claim equality and cache/session identity exclude
the process-local instant, so equal claims are not evidence of current authority.
Proofs are not persisted or transmitted as replacement credentials.

Run the relevant tests:

```sh
cargo test -p rembrane-contracts -p rembrane-application -p rembrane-mcp \
    -p rembrane-remote-mcp-http --locked --offline
```

Tests cover clone/non-renewal behavior, invalidation by an expired epoch
observation, slow protocol/tool verification, and expired proof rejection
before MCP startup environment/provider access and tool worker admission.
Tenant construction checks before admission and inside blocking work. The
Tower adapters check before readiness and again immediately before calling
the service, across client POST, initialization, stream GET, and DELETE.
Blocked-construction/readiness tests prove expired proofs never start SDK work.

Registry establishment and reserved-session commit reject expired proofs even
when the request's original epoch snapshot has not advanced. A delayed-response
Tower fixture proves that late initialization is not published, pending capacity
is released, and compensation reuses the exact cached tenant service. That
fixture is not a real SDK listener. Internal compensating termination can clean
up an already created session after expiry; client DELETE cannot use that path.
Shared initialization retains its validated Host/Origin for both operations.
Compatibility initialization failures use a separate internal rollback:
the session binding, including its expiry ceiling, must match exactly. Tests
deny foreign/scope/expiry substitutions and repeated cleanup, while a delayed
failure fixture proves that an elapsed original proof can release its unchanged
binding. Changed bindings are not removed.

Custom dispatcher implementations must enforce proof lifetime after their own
waits and before execution; the ports document that obligation. The trusted
epoch-second sample must be supplied correctly by the HTTP host. These checks
do not re-introspect revocation, force-cancel an admitted mutation, or close an
already opened event stream. Fresh token verification, canonical membership
reauthorization, provider timeouts, and live expiry/revocation tests for the
actual remote listener remain necessary.
Concurrent cache pruning during late initialization/compensation also needs
actual SDK session-state verification. The library race fixture now removes
and replaces the cache entry before late-failure compensation, proving cleanup
uses the original service, not its replacement.

## Initialization service ownership during compensation

Tower initialization attaches a private, process-local service handle to
`InitializedRemoteMcpSession`. The shared and borrowing orchestrators use
`terminate_initialized` with the owned result on commit failure. That path
checks the original verified claims and validated HTTP metadata, then selects
the retained service on a bounded blocking worker. It never re-enters the
factory or depends on an unpruned cache entry. `into_parts` discards the private
handle and is appropriate after successful commit, not before compensation.
Debug output and logical result equality do not expose or prove the handle.

The four additional remote-adapter tests cover:

- pruning and replacing the exact cache identity while initialization waits,
  followed by cleanup on the original service and no additional factory call;
- missing handles, wrong service type, claim/header substitution, saturated
  and closed capacity, and successful exact-handle selection;
- clone execution off the executor and capacity retained after waiter abort
  until actual blocking completion;
- redacted clone panic and independent-handle recovery without cache poisoning.

Direct Tower cleanup shares the process factory-worker budget; tenant-aware
cleanup uses its dispatcher budget. `CleanupUnavailable` is a closed error
for overload/closed capacity or worker failure. The actual HTTP host still
needs to map this failure appropriately; these tests do not establish a live
HTTP overload response or guaranteed cleanup after caller cancellation.

Tower service clones must share the same session state and be lightweight.
The cached pinned `rmcp` 3.7.0 source keeps its session manager in an `Arc`
across clones; source inspection is not executable transport verification.
Arbitrary custom `Clone`/`Drop` implementations are not automatically safe.
Stateful custom dispatchers must override `terminate_initialized` with their
own retained ownership. Its default and the legacy `terminate` port preserve
stateless/caller-managed compatibility but do not solve cache reselection for
custom stateful implementations. Real SDK lifecycle, cancellation, stream
expiry/revocation, and deployment/recovery tests remain pending.

Provider authors should also run the shared Rust conformance harness against a
disposable provider tenant:

```text
verify_semantic_provider(&mut provider, "unique-test-namespace")
```

Inspect the exact compatibility registry compiled into the local CLI:

```sh
target/debug/rembrane providers list | jq .

target/debug/rembrane providers check \
  --provider rembrane.native \
  --adapter-version 0.1.0-alpha.1 \
  --allow-experimental \
  --allow-provider-plaintext | jq .
```

To consume a newer release registry without rebuilding, provide the registry,
its detached signature, and a separately trusted release public key together:

```sh
./scripts/verify-provider-registry-bundle.sh \
  provider-registry-bundle/ \
  provider-registry-signing-public.pem

target/debug/rembrane providers check \
  --provider rembrane.native \
  --adapter-version 0.1.0-alpha.1 \
  --allow-experimental \
  --allow-provider-plaintext \
  --expected-registry-sha256 <previously-reviewed-registry-sha256> \
  --minimum-registry-generated-at 2026-10-25T05:03:44Z \
  --registry provider-registry.json \
  --signature provider-registry.json.sig \
  --public-key provider-registry-signing-public.pem
```

Do not obtain the public key from the same untrusted location as the registry.
The bundle directory contains exactly `provider-registry.json`, its checksum,
and its signature; keep the public key outside that directory. Verification
checks the exact inventory, checksum, signature, registry schema, provider
states, and conformance evidence before the registry reaches the CLI.
The resulting selection receipt includes the SHA-256 fingerprint of the
canonical Ed25519 public-key DER bytes for trust-anchor auditing.
Persist the accepted receipt's `registrySha256` and `registryGeneratedAt` when
an integration needs rollback resistance, then supply them as the exact digest
or minimum generation constraint on its next selection.

The CLI can run the same destructive-fixture suite for adapters compiled into
the current build. Always use a unique disposable namespace:

```sh
target/debug/rembrane providers test \
  --provider rembrane.native \
  --namespace local-check | jq .
```

The harness writes two versions of one fixture and deletes it while checking
protocol compatibility, exact replacement semantics, workspace isolation,
result limits, version-bounded deletion, and deletion propagation.
Successful CLI runs emit strict JSON containing the exact provider build,
protocol, disposable namespace, suite identity, suite version, and one pass
record for each of the six required behaviors. Validate retained evidence
against `spec/semantic-provider-conformance-result.schema.json` before registry
review.

Run the same suite against a disposable Mem0 OSS instance only after verifying
that the target contains no production records:

```sh
MEM0_BASE_URL=https://mem0.example \
MEM0_API_KEY_REFERENCE=file:/run/secrets/mem0-api-key \
MEM0_WORKSPACE_LOOKUP_SECRET_REFERENCE=file:/run/secrets/mem0-workspace-key \
target/debug/rembrane providers test \
  --provider mem0.oss \
  --namespace mem0-20261024-a8f21c \
  --allow-provider-plaintext | jq .
```

The explicit acknowledgement is mandatory because semantic conformance sends
plaintext fixtures to Mem0. Credential locators are read from the process
environment and resolved inside the deployment; raw values remain compatible
defaults when locators are absent and are never accepted as command-line
arguments. External namespaces accept only 16-80 safe ASCII characters;
generate a fresh random suffix for every run.

Run Supermemory v5 conformance with the same safeguards:

```sh
SUPERMEMORY_BASE_URL=https://api.supermemory.ai \
SUPERMEMORY_API_KEY_REFERENCE=file:/run/secrets/supermemory-api-key \
SUPERMEMORY_WORKSPACE_LOOKUP_SECRET_REFERENCE=file:/run/secrets/supermemory-workspace-key \
target/debug/rembrane providers test \
  --provider supermemory.v5 \
  --namespace supermemory-20261024-a8f21c \
  --allow-provider-plaintext | jq .
```

The adapter waits for scoped canonical ID/version visibility before considering
asynchronous ingestion complete and requires exact deletion confirmation.

External HTTP sidecars can run the equivalent black-box suite. The bearer
token is read from the environment and written only to a mode-0600 temporary
header file, so it does not appear in the `curl` process arguments:

```sh
REMBRANE_PROVIDER_BASE_URL=https://provider.example \
REMBRANE_PROVIDER_TOKEN='replace-from-secret-store' \
./scripts/test-provider-http.sh unique-disposable-namespace
```

The runner accepts loopback HTTP for local development and requires HTTPS
elsewhere. It mutates and deletes its conformance fixture; never point it at a
namespace that contains production records.

CI sets `REMBRANE_RUN_LOOPBACK_TESTS=1` so `scripts/check-protocols.sh` runs the
HTTP runner against an authenticated loopback mock sidecar, verifies final
fixture cleanup, and asserts that captured output does not contain the bearer
token. Restricted sandboxes still syntax-check both scripts and verify that
remote plaintext HTTP is rejected.

External key-provider sidecars have a separate non-destructive black-box suite:

```sh
REMBRANE_KEY_PROVIDER_BASE_URL=https://keys.example \
REMBRANE_KEY_PROVIDER_TOKEN='replace-from-secret-store' \
./scripts/test-key-provider-http.sh unique-request-namespace
```

It verifies authentication, protocol and algorithm discovery, exact envelope
shape, bounded plaintext, round-trip opening, workspace-context substitution
denial, unknown-key denial, and bearer-token redaction. The runner sends
disposable plaintext and must only target a test provider.

## Manual local setup

Build binaries:

```text
cargo build --workspace
```

Create a disposable development profile:

```text
export REMBRANE_DATABASE="$PWD/.rembrane/rembrane.db"
export REMBRANE_PRINCIPAL_ID=principal_local
export REMBRANE_WORKSPACE_ID=workspace_personal
export REMBRANE_CLIENT_ID=assistant_local
export REMBRANE_READ_SCOPES=global,domain:development,entity:project_local
# Optional; keep empty unless testing privileged travel source disclosure.
export REMBRANE_READ_PERMISSIONS=
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_WORKSPACE_KEY_HEX="$(openssl rand -hex 32)"
export REMBRANE_API_TOKEN="$(openssl rand -hex 32)"
```

The CLI creates missing database, backup, and restore directories with mode
`0700` on Unix. If `.rembrane` already exists, protect it before use:

```text
chmod 700 .rembrane
```

Do not put real keys directly in shell history, command arguments, committed
configuration, screenshots, logs, or issue reports.

On macOS, the equivalent Keychain-backed profile is:

```text
export REMBRANE_KEY_PROVIDER=macos-keychain
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_KEYCHAIN_SERVICE=org.rembrane.workspace.test
export REMBRANE_KEYCHAIN_ACCOUNT="$REMBRANE_WORKSPACE_ID"
export REMBRANE_KEYCHAIN_HISTORICAL_KEYS=
openssl rand -hex 32 | /usr/bin/security add-generic-password \
  -U -s "$REMBRANE_KEYCHAIN_SERVICE" -a "$REMBRANE_KEYCHAIN_ACCOUNT" -w
unset REMBRANE_WORKSPACE_KEY_HEX
```

Use a disposable Keychain item for tests and delete it after testing. Never use
the `security -A` option, which would permit unrestricted item access.

On a Linux desktop with an unlocked Secret Service collection:

```text
export REMBRANE_KEY_PROVIDER=linux-secret-service
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_SECRET_SERVICE_SERVICE=org.rembrane.workspace.test
export REMBRANE_SECRET_SERVICE_ACCOUNT="$REMBRANE_WORKSPACE_ID:key_v1"
export REMBRANE_SECRET_SERVICE_HISTORICAL_KEYS=
openssl rand -hex 32 | /usr/bin/secret-tool store \
  --label="Disposable Rembrane test key" \
  rembrane-service "$REMBRANE_SECRET_SERVICE_SERVICE" \
  rembrane-account "$REMBRANE_SECRET_SERVICE_ACCOUNT" \
  rembrane-key-id "$REMBRANE_WORKSPACE_KEY_ID"
unset REMBRANE_WORKSPACE_KEY_HEX
```

Delete the item after testing using the desktop keyring manager or
`secret-tool clear` with the same three attributes.

On Windows, create a disposable CurrentUser DPAPI blob with the provisioning
script in the README, using a path beneath `$env:TEMP`, then configure:

```powershell
$env:REMBRANE_KEY_PROVIDER = "windows-dpapi"
$env:REMBRANE_WORKSPACE_KEY_ID = "local-key-v1"
$env:REMBRANE_DPAPI_BLOB_PATH = "$env:TEMP\rembrane-test-key.dpapi"
$env:REMBRANE_DPAPI_HISTORICAL_KEYS = ""
Remove-Item Env:REMBRANE_WORKSPACE_KEY_HEX -ErrorAction SilentlyContinue
```

Run the Rust test suite from the same Windows user account. The Windows CI job
also performs a live DPAPI protect/unprotect round trip and warnings-as-errors
lint. Delete the disposable blob after testing.

To exercise a disposable customer-controlled key-provider sidecar instead:

```text
export REMBRANE_KEY_PROVIDER=http
export REMBRANE_KEY_PROVIDER_BASE_URL=https://keys.example
export REMBRANE_KEY_PROVIDER_TOKEN='replace-from-secret-store'
export REMBRANE_KEY_PROVIDER_REQUIRE_HISTORICAL_KEYS=true
unset REMBRANE_WORKSPACE_KEY_HEX
```

Run `rembrane doctor --privacy` before writing data and confirm that the
reported key provider and redacted outbound origin match the intended
deployment.

Initialize and exercise the encrypted CLI:

```text
target/debug/rembrane init \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID"

target/debug/rembrane doctor \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --privacy

target/debug/rembrane doctor \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --json

target/debug/rembrane backup \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --output .rembrane/rembrane-backup.rembrane

target/debug/rembrane restore \
  --input .rembrane/rembrane-backup.rembrane \
  --database .rembrane/rembrane-restored.sqlite \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID"

target/debug/rembrane fingerprint-git --repository "$PWD"

target/debug/rembrane remember \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --content "Call me Hippo"

target/debug/rembrane remember \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --entity project_local \
  --content "Use Rust for the Rembrane core"

target/debug/rembrane recall \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --client "$REMBRANE_CLIENT_ID" \
  --purpose personalize-assistant \
  --query "What should I call the user?"

target/debug/rembrane recall \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --client "$REMBRANE_CLIENT_ID" \
  --entity project_local \
  --purpose continue-project \
  --query "Which language should power the Rembrane core?"

target/debug/rembrane remember \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --domain travel \
  --content "Prefer nonstop flights"

target/debug/rembrane recall \
  --database "$REMBRANE_DATABASE" \
  --principal "$REMBRANE_PRINCIPAL_ID" \
  --workspace "$REMBRANE_WORKSPACE_ID" \
  --client travel-assistant \
  --domain travel \
  --entity trip_berlin \
  --purpose continue-trip-planning \
  --query "What are my flight preferences and trip constraints?"
```

The JSON doctor result validates against `spec/local-doctor.schema.json` and
omits principal and workspace identifiers so installers, launchers, agents,
and bots can consume health without receiving tenant-routing metadata. Failed
checks exit non-zero and return only the closed `doctor_failed` JSON code.

## MCP client profile

Configure an MCP-capable client to launch:

```json
{
  "command": "/absolute/path/to/target/debug/rembrane-mcp",
  "env": {
    "REMBRANE_DATABASE": "/absolute/path/to/.rembrane/rembrane.db",
    "REMBRANE_PRINCIPAL_ID": "principal_local",
    "REMBRANE_WORKSPACE_ID": "workspace_personal",
    "REMBRANE_CLIENT_ID": "assistant_local",
    "REMBRANE_READ_SCOPES": "global,domain:development,entity:project_local",
    "REMBRANE_READ_PERMISSIONS": "",
    "REMBRANE_WORKSPACE_KEY_ID": "local-key-v1",
    "REMBRANE_WORKSPACE_KEY_HEX": "<development-key>"
  }
}
```

Use the client’s protected secret mechanism when it provides one. A literal key
in a desktop configuration file is only acceptable for disposable testing.

## REST

Start the local server:

```text
target/debug/rembrane-api
```

It binds to `127.0.0.1:8787` by default. Run the Postman collection:

```text
postman collection run tests/postman/rembrane-local.postman_collection.json \
  --env-var baseUrl=http://127.0.0.1:8787 \
  --env-var apiToken="$REMBRANE_API_TOKEN" \
  --env-var workspaceId="$REMBRANE_WORKSPACE_ID" \
  --env-var principalId="$REMBRANE_PRINCIPAL_ID"
```

## Current verification limitation

If dependency download is unavailable, the SQLite and static checks can still
run, but Rust compilation and protocol smoke tests cannot be considered
complete. A green CI run is required before calling a commit test-ready.
