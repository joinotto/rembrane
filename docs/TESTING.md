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

The runtime gate has separate `--build` and `--live` modes; strict release
readiness requires the live concrete-driver matrix as well as SQL fixtures.
Run its fake-Cargo regression tests with:

```sh
node scripts/test-postgres-runtime-gate.mjs
```

These tests verify gate decisions and diagnostic redaction. They do not compile
the missing driver or constitute live database proof. See the
[runtime gate requirements](PRODUCTION_TESTING.md#concrete-postgresql-runtime-gate).

## Official MCP HTTP release-gate tests

```sh
node scripts/test-streamable-http-runtime-gate.mjs
```

These 64 fake-Cargo cases exercise resolved SDK/adapter dependencies, target
admission, separate binary/test compilation decisions, exact test execution
counts, and diagnostic redaction. They do not compile Rust or exercise an SDK
HTTP service. The static suite includes them.

The real checker offers `--build` and `--runtime`; runtime is the default and
mandatory for production readiness. It rejects source markers and disabled or
absent integration targets, and requires all eight named actual-SDK tests.
The runtime integration remains missing, so the real checker must still fail.
See the [SDK runtime requirements](PRODUCTION_TESTING.md#official-mcp-http-runtime-gate).
Passing that in-process matrix will not replace real HTTPS staging evidence.

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
the pre-dispatch incarnation and session binding, including its expiry ceiling,
must match exactly. Tests
deny foreign/scope/expiry substitutions and repeated cleanup, while a delayed
failure fixture proves that an elapsed original proof can release its unchanged
binding. Changed bindings are not removed.

Each established binding owns a unique process-local identity retained by an
opaque `RemoteSessionMutationGuard`. `establish_guarded` captures it atomically
for compatibility initialization; `capture_mutation_guard` revalidates and
captures an existing binding before DELETE dispatch. Shared paths capture under
their local lock, then release the lock over downstream work. Borrowing paths
use the same completion checks.

`commit_termination` requires the captured incarnation and current authority;
`rollback_establishment` requires the incarnation and exact unchanged claims/
expiry ceiling but still allows internal cleanup after original proof expiry.
Same-ID/same-claims replacement, even with an identical proof/deadline, cannot
alias the guard. Retaining the original identity also prevents allocator address
reuse. Debug output exposes no ID or identity address.

Three registry regressions cover replacement, foreign registries, pruning, and
repeated completion. Two synchronized Tower fixtures pause after dispatch begins,
replace the binding with identical claims, then release late DELETE success or
initialization failure. Both failed before this fix and now preserve the successor.
The pre-alpha rollback API no longer accepts a raw session ID; capture its guard
before dispatch. Synchronous `terminate` is not an async completion API.

These guards protect local registry mutation only: they do not undo already
executed SDK operations, cancel queued tools, close opened streams, or establish
external-store consistency. They are not serialized or reusable across process
restarts. A real listener/session store needs its own verified incarnation,
cancellation, and revocation behavior.

Anonymous initialization reservations similarly retain a unique slot identity,
not only a per-registry counter. Commit and cancellation check both before
changing the pending-capacity ledger. Equality compares slot identity as well
as the counter; diagnostics still redact both. Tokens remain move-only and
process-local.

Three application regressions cover foreign commit/cancel with deliberately
matching counters and cross-instance token equality. The foreign operations
previously returned success; they now deny and preserve both registries'
capacity. As before, an owned commit consumes its reservation even when
session establishment subsequently fails. Passing a token to the wrong registry
consumes the input token but changes neither ledger; callers must retain correct
ownership, and this rejection is not cross-registry cleanup or recovery.
Existing shared initialization cancellation/admission fixtures still pass;
live SDK cancellation and provider cleanup remain unverified.

Session bindings also retain the original process-local deadline, independently
of their epoch expiry ceiling. Refresh can shorten but never renew that deadline.
`is_expired` and registry pruning enforce both clocks, so a stale or rolled-back
epoch sample cannot keep an elapsed session alive or consuming capacity.

`revalidate_access` propagates the binding deadline into the returned
`VerifiedRemoteAccess` while preserving every signed claim. Connection, tool,
HTTP request, and termination authorization use this path, including owned/
shared POST and DELETE workers. Queued dispatch and guarded response delivery
therefore receive the original session ceiling rather than a fresh token's
longer lifetime. The older borrowed `revalidate` checks/narrows the binding but
does not mutate the caller's proof; dispatch integrations must use the
proof-carrying path.

Binding equality compares claims and the epoch ceiling, not current lifetime.
Internal rollback may still use an elapsed or locally narrowed original proof
for exact signed-context cleanup; equality must never authorize a request.
Tests separately verify real elapsed-session denial/pruning, proof-ceiling
propagation through each authorization path, and non-renewal under refresh.
These remain in-process session tests. Replay is unsupported, and actual
SDK/session-manager behavior is still unverified.

Client-requested Tower DELETE must return an HTTP `Response<Body>` (with a
generic sendable body), not an arbitrary transport output. Direct and
tenant-selected dispatchers reject every non-success status with opaque
`InvalidSdkResponse`. The orchestration does not remove a binding on that
error, allowing a currently authorized retry; 404 is not silently treated as
proof that the correct session was deleted.

Three regression matrices exercise nine non-success statuses across borrowing,
owned/shared, and tenant-selected routes, then confirm HTTP 200/202/204 retry
success and local removal. In the pinned SDK source, client DELETE closes the
session before returning 202; accepting that successful status preserves its
contract. These in-process HTTP-response fixtures are not live SDK proof.
Custom `AuthorizedRemoteMcpSessionDeletionDispatcher` implementations must
return `Ok` only for confirmed protocol deletion, not successful transport I/O.
The pre-alpha Tower deletion implementation now requires an HTTP response;
custom non-HTTP protocols retain the explicit port and its confirmation duty.

Client DELETE now also requires the `RemoteSessionDispatchGuard` captured under
the same registry lock as its local mutation-completion guard. The pre-alpha
`AuthorizedRemoteMcpSessionDeletionDispatcher::terminate` signature adds this
mandatory guard immediately after `session_id`. Custom dispatchers must retain
it and call `ensure_current(&session_id, &access)` after waits and immediately
before starting downstream deletion; an old proof or a newly captured replacement
is not equivalent authority.

Direct and tenant-selected Tower DELETE retain the guard in HTTP extensions,
rechecking before dispatch and after readiness. Tenant factory workers check
before and after construction, and removed or substituted guards are denied
before provider selection. All session-bearing client requests now require the
guard; DELETE no longer has a missing-guard exception. Borrowing and owned/shared
orchestration capture both guards before dispatch, and still commit local removal
only after confirmed HTTP success.

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline queued_session_delete
cargo test -p rembrane-remote-mcp-http --locked --offline client_delete_rejects
```

The readiness regression first reproduced one downstream DELETE call after
local removal. It now denies before that call, including a same-claims
replacement. The tenant-wait matrix now covers DELETE alongside GET/POST; a
second new test covers removed guards and session/proof substitution without
provider construction. Existing HTTP-status/retry, unlocked dispatch,
late-completion, and expired-client-versus-internal-cleanup tests still pass.

Internal compensating termination remains a separate port and does not use
client admission; it may clean up an already initialized exact retained SDK
service with an elapsed original proof. These fixtures do not prove cancellation
or replacement safety of an SDK operation already admitted, or live SDK cleanup.
Keep those actual-listener/session-manager release requirements open.

Established-session POST proofs retain a private `RemoteSessionId` in their
protocol metadata only after successful registry authorization. HTTP header
parsing alone leaves it absent. Borrowing Axum wrappers preserve this field
when replacing transport-neutral metadata; owned/shared workers attach it
after revalidation. Direct and tenant-selected Tower dispatchers reconstruct
`Mcp-Session-Id` from this typed field, never by forwarding arbitrary input
headers. Both retain the canonical workspace extension and omit bearer
credentials. The shared path also retains its validated Host/Origin.

Three regressions check these routes, unknown and foreign sessions, exact
scope-ceiling substitution, stateless rejection, and sessionless
initialization. Debug output reveals only session presence, not its value.
Legacy caller-declared initialization remains a compatibility fixture, not
the official SDK-generated initialization path; the new forwarding field is
for established-session POSTs only. Actual SDK lifecycle tests remain required.

Session GET/POST now also capture `RemoteSessionDispatchGuard` under the
registry authorization lock, before any asynchronous factory/readiness wait.
The guard couples the exact session incarnation, request claims, and original
proof lifetime. Deletion, pruning, rollback, or registry destruction permanently
invalidates every clone; a same-ID/same-claims replacement cannot revive it.
Both registry revalidation APIs also shorten a shared dispatch deadline, so
already captured requests observe a later narrowed session ceiling without
requiring another capture or prune.

Borrowing Axum wrappers retain this guard when replacing protocol metadata.
Direct/tenant Tower GET/POST preserve it in HTTP extensions and check it before
dispatch and after readiness; tenant factory workers check before and after
construction as well. The MCP handler checks the coupled session header and
guard before admission, at worker entry, and during canonical authorization
after waiting for its state lock. Stateless requests remain separate and do not
require a session guard. Missing, duplicate, or substituted session metadata
must not become stateless authority.

```sh
cargo test -p rembrane-application --locked --offline dispatch_guard
cargo test -p rembrane-remote-mcp-http --locked --offline session_dispatch_tests
cargo test -p rembrane-mcp --locked --offline removed_session_is_denied
cargo test -p rembrane-mcp --locked --offline real_tool_requires_exact_session_guard
```

Two synchronized readiness regressions first reproduced GET/POST dispatch
after deletion; the fix also denies same-claims replacements. Four transport
tests cover readiness, tenant construction, and borrowing handoffs. Four
registry tests cover permanent removal, request substitution, original expiry,
and later shared-ceiling reduction. Two MCP SDK-context tests exercise real
encrypted tool admission, including a removed/replaced session while waiting
for the canonical store, with no mutation.

The pre-alpha session-stream `into_parts` API now returns the dispatch guard
as its third element; custom transports must retain and recheck it after waits.
POST custom transports can obtain it from `authorized_session_guard()` and
must preserve the coupled session ID/proof. Guard equality describes immutable
identity/claims, never current authority.

These guards provide process-local admission checks, not token introspection,
idle-stream wakeups, forced cancellation of already admitted operations, or
distributed session consistency. Real SDK HTTP propagation and cleanup remain
unverified; client DELETE now has guarded admission, but already admitted SDK
deletion and compensating cleanup still need actual SDK incarnation/replacement
proof. Continue to require response guarding and real revocation monitoring
for opened streams.

Session-bound GET uses the separate
`AuthorizedRemoteMcpSessionEventStreamDispatcher` consuming port. The private
`AuthorizedRemoteMcpSessionEventStream` couples the session with its
reauthenticated canonical tenant proof, original monotonic ceiling, and
validated HTTP metadata. Owned/shared
`authorize_and_dispatch_session_event_stream` APIs verify on bounded workers
and revalidate locally without holding the registry lock over verification
or dispatch. `authorize_axum_session_event_stream` is a synchronous borrowing
compatibility API with the same session and header checks, not an automatically
offloaded network-verification path.

Direct and tenant-selected Tower dispatch build GET from this proof, retain
`Mcp-Session-Id`, and omit bearer credentials, arbitrary input headers, and
request bodies. Readiness and service-factory waits cannot extend the original
session ceiling. Eight new regressions cover these paths, each bound identity/
scope substitution, unknown sessions, unlocked dispatch, actual elapsed
factory/readiness denial, and continued stateless/session API separation.
They are not real SDK stream-delivery or revocation tests.

Both GET header boundaries reject any `Last-Event-ID` with HTTP 400 before
verification, including empty, duplicated, and non-text values. Replay is not
silently ignored; event-store isolation and cursor authorization must be
verified before adding resume support. Stateless GET still rejects session
headers, and the session-bound API requires one. Neither API automatically
guards response delivery or attaches a live revocation controller.

Custom dispatcher implementations must enforce proof lifetime and the captured
session guard after their own waits and before execution; the trusted
epoch-second sample must be supplied correctly by the HTTP host. These checks
do not re-introspect revocation, force-cancel an admitted mutation, or close an
already opened event stream. Fresh token verification, canonical membership
reauthorization, provider timeouts, and live expiry/revocation tests for the
actual remote listener remain necessary.
Concurrent cache pruning during late initialization/compensation also needs
actual SDK session-state verification. The library race fixture now removes
and replaces the cache entry before late-failure compensation, proving cleanup
uses the original service, not its replacement.

## Remote response delivery after admission

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline response_guard
```

`RemoteMcpGuardedBody` and `guard_remote_mcp_response` add a delivery boundary
using the existing Axum HTTP body and Tokio timer/watch primitives. They are
opt-in helpers; the current Tower dispatchers do not automatically wrap
responses, and the official SDK listener remains unwired.

The guard takes an original `VerifiedRemoteAccess` and a subscription from
`RemoteMcpStreamRevocation`. Every verified claim must match. Its deadline is
the earlier of the original proof and controller proof; equal claims or a
new subscription cannot renew either deadline. An expired proof, revoked
subscription, or loss of all controller owners denies construction/delivery.

During polling, the guard checks before and after the provider body. It stops
both data and trailer frames, emits one opaque body error, drops the underlying
body, and then returns EOF. Timer/watch wakeups terminate idle streams even
without provider activity. Underlying body errors are discarded instead of
exposing their diagnostics. Normal completion and consumer cancellation release
the subscription; a monitor can use `controller.closed().await` to release its
own resources when no subscriptions remain.

`RemoteMcpGuardedBody::new_with_session` and
`guard_remote_mcp_session_response` additionally retain the exact captured
`RemoteSessionDispatchGuard`, session ID, and request proof. Before and after
every provider poll they deny removed/replaced sessions and the latest shortened
session deadline. An idle per-body timer rechecks that local authority every
100 ms while the body is polled; it spawns no background task, performs no
introspection/storage I/O, and does not lock the global registry. The small
per-incarnation deadline lock never spans an await. Scheduler delays can delay
idle cleanup; frames still require a fresh check at each delivery boundary.
Admission must bound active bodies and the resulting timer/poll work.

The existing controller remains mandatory for token/membership revocation;
local session checks do not provide either. Do not apply session composition
to a DELETE confirmation after intentionally removing its binding. SDK
initialization wrapping still requires exact cleanup ownership on rejection.
Both helpers are opt-in and remain unwired to the actual SDK HTTP listener.

Consumer drop now clears all authorization futures/subscriptions before
invoking the provider body's destructor. One regression first reproduced a
provider destructor observing a still-live subscription during cancellation;
it now observes zero. Denial, EOF, final-frame completion, constructor failure,
and cancellation share the same idempotent teardown order.

Integration obligations:

- Keep a controller owner alive in a bounded authority monitor or registry.
  A temporary handler-local controller dropped when returning the response
  intentionally revokes that response; a subscriber does not own the monitor.
- Poll bodies inside a Tokio runtime with its timer driver enabled.
- Connect sticky `revoke()` to actual token, canonical membership, and
  session invalidation. A channel alone is not introspection. Bound active
  streams, controllers, and monitor work separately from tenant service caching.
  Monitor failure must revoke retained controllers, even when another owner
  still holds a clone.
- Wrap SDK response bodies while retaining exact initialization session/service
  ownership. If wrapping rejects a successfully initialized response, perform
  the existing exact-service compensation; do not reconstruct cleanup from
  a refreshed cache.
- Keep fresh per-operation authorization. This guard stops future body frames,
  not already released/buffered frames, transmitted bytes/headers, or already
  admitted mutations.

Thirty-three body-level tests cover active delivery, trailers, idle expiry and
revocation, controller loss/clones, all claim substitutions, independent
tenants, mid-poll revocation, shortest-deadline non-renewal, opaque failure,
status/header preservation, EOF, and consumer/monitor cleanup. Seven new cases
add exact-session frame denial, same-claims replacement, idle removal/rollback/
pruning/registry-drop wakeups, later deadline reduction, mid-poll data/trailer
denial, session/proof substitution, preserved controller authority, and
cancellation teardown ordering. These are not
live HTTP, SDK session-manager, provider, or remote revocation evidence.

### Shared response admission

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline response_budget
```

`RemoteMcpResponseBudget::new(global_limit, workspace_limit)` uses existing
Tokio semaphores with positive limits, a per-workspace ceiling no greater than
the global limit, and a configuration safety ceiling of 10,000. This ceiling
is not a measured capacity or recommended production setting. Share one
budget across all routes, instances of a tenant factory, and clones of the
local server. Independent processes need a separate deployment-wide strategy.

Reserve using the verified access proof **before** SDK/provider dispatch,
hold the move-only permit through dispatch/readiness waits, and consume it in
`RemoteMcpGuardedBody::new_with_permit` or
`RemoteMcpGuardedBody::new_with_session_and_permit`. Both quotas remain owned
while the provider body is polled or destroyed; the subscription closes before
the provider destructor, and capacity returns only afterward. Rejection, EOF,
final-frame completion, revocation, cancellation, and destructor unwind follow
the same ownership rule. Retaining a closed wrapper does not retain capacity.
Equal refreshed claims cannot renew the original reservation deadline.

Admission rejects immediately rather than creating an unbounded waiter
queue. Quota keys come from verified workspace identity; all principals and
clients in that workspace share its quota. Workspace IDs reused across trusted
issuers/resources conservatively share capacity in this budget, not memory or
authorization. Private weak buckets are pruned under churn and protected by a
short lock with no provider I/O or await. Errors/debug output omit identities.

Seven budget tests cover limits, shared quotas, concurrent same-workspace
admission, proof/expiry binding, stale bucket cleanup, poisoned metadata, and
redaction. Five additional body tests cover eight completion/rejection paths,
poll ownership, synchronized blocked cleanup with unrelated tenant progress,
destructor unwind, and same-claims non-renewal. The 148 remote tests pass.

These APIs are opt-in: existing unbudgeted constructors/helpers remain
available for compatibility and Tower dispatchers do not automatically reserve.
The actual SDK listener must wire mandatory admission across every response
path and map exhaustion to an appropriate opaque overload response. Pending
dispatch cancellation must retain quota until actual work completes; dropping
a future must not release quota while a detached task continues. Independently
running provider tasks, producer allocations/buffers, monitor tasks, and SDK
session resources need their own limits. Unit tests do not establish live listener
cleanup, scheduling behavior, fairness, or a production operating envelope.

### Reserved delivery policy

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline delivery_limits
cargo test -p rembrane-remote-mcp-http --locked --offline reserved_delivery_policy
```

Create validated `RemoteMcpDeliveryLimits` and use
`RemoteMcpResponseBudget::new_with_delivery_limits`. Every permit retains the
same immutable policy; both budgeted body constructors automatically enforce
it. No consumer API changes or resets a body's counters. The capacity-only
`new` budget and unbudgeted helpers do not acquire a delivery policy implicitly.

The five configured limits are:

- maximum bytes in one data frame;
- cumulative data bytes across the response;
- cumulative trailer bytes, counting each name and raw value, including
  duplicate header values and repeated trailer frames;
- cumulative trailer fields, counting duplicate values separately;
- total frames, including empty data and empty trailer frames.

Data and frame limits must be positive; a single-frame allowance cannot exceed
total data allowance. Zero trailer allowances reject nonempty trailers. All
counters use checked arithmetic; exact boundaries are allowed, but overflow or
any exceeded limit produces one opaque `DeliveryLimitExceeded` error, discards
the offending frame, closes delivery, and follows normal teardown ownership.
The rejected frame is dropped before provider-body teardown. Revocation/expiry
checks still run before and after provider polling and take precedence over a
delivery limit failure. They also run after delivery accounting, before a
candidate frame can be returned.

Size hints are capped by remaining data allowance, but actual frame lengths
are checked regardless of a provider's advertised hint. This is not streaming
pagination or a guaranteed complete JSON/SSE message: a limit failure can
interrupt a response after earlier frames were delivered. The actual SDK/HTTP
integration must handle that failure and document reconnection/retry behavior,
not return a successful truncated result or silently retry a mutation.

Seven accounting tests cover configuration, exact/cumulative limits,
duplicate trailers, empty frames, overflow, and size hints. Four body tests
exercise seven rejection paths, exact boundaries with separate response
counters, revocation priority, and a misleading zero-byte provider hint. The
oversized-frame case failed before enforcement and now passes.

These controls bound bytes and metadata **forwarded by the guard**. They cannot
prevent allocation before a provider returns a frame or constrain an oversized
backing buffer behind a small `Bytes` slice, compressed wire bytes, HTTP response
headers already returned, or consumer/network queues. Producer and transport
limits, listener integration, live load tests, and measured deployment-specific
values remain required. There is deliberately no claimed production default.

### Discarded provider-resource cleanup

```sh
cargo test -p rembrane-remote-mcp-http --locked --offline rejected_provider_objects
cargo test -p rembrane-remote-mcp-http --locked --offline discard
```

A rejected frame can own provider buffers via `Bytes::from_owner`; a raw body
error can own driver resources. Cleanup closes all authorization first, drops
the rejected object, destroys the provider body, and only then returns quota.
An internal owned cleanup guard retains the body and quota during discard, so
an unwinding discarded-resource destructor still destroys the body and returns
quota with the public wrapper already closed.

One regression was run before the fix with both ordering failures: frame
discard observed one active authorization subscriber, and raw-error discard
could reserve quota that should still have been held. Three new tests now cover
limit/revocation/transport rejection, synchronized blocked frame/error discard
with unrelated workspace progress, and frame/error destructor unwind while
retaining the closed wrapper. Both rejected-resource and body teardown happen
exactly once in these fixtures.

Destruction is synchronous. These tests do not prove executor isolation:
provider resource/body destructors must be bounded and nonblocking, or the
integration must arrange bounded off-executor cleanup with capacity retained.
They also do not bound detached provider/SDK tasks or references held elsewhere.
A process abort or two simultaneous destructor panics is not recoverable
cleanup evidence. Actual SDK cancellation and shutdown verification remain open.

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
must pass a live DPAPI protect/unprotect round trip and warnings-as-errors
lint. Delete the disposable blob after testing.

The resolver keeps `-Command` as a fixed script, supplying reference metadata
only through private per-child `REMBRANE_DPAPI_BRIDGE_BLOB_PATH` and
`REMBRANE_DPAPI_BRIDGE_KEY_ID` overrides. These are internal transport values,
not new setup variables or plaintext keys. The parent process environment is
not mutated. Captured key output and errors retain the zeroizing/opaque-error
boundary. Fixture protection receives only the synthetic key through stdin;
neither bridge script uses trailing `$args`.

On 2026-10-27, the latest published Windows CI job inspected from run
`40189971578` at revision `bc064779727611f5871b7e361c174fa2d830d01d`
had failed on null `$args` in the protection fixture. A cross-platform
regression reproduced the same unsafe invocation structure for the resolver:
private reference values appeared after `-Command` instead of being literal
input data. The two command-construction tests now pass:

```sh
cargo test -p rembrane-crypto-rustcrypto --locked --offline windows_dpapi_bridge
```

These tests inspect the exact shared production command builder; they do not
execute Windows PowerShell or DPAPI. The corrected Windows-only live fixture
also checks a path with spaces/apostrophes and rejects a mismatched key-ID
entropy. Its hosted rerun is still required before restoring the live-verification
checkbox. The older failed run and locally passing structure tests must not
be reported as current Windows success.

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
