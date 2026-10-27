# First production release plan

Status assessment: 2026-10-27. Rembrane remains pre-alpha.

This is the execution plan for the first supported infrastructure release,
not a promise that every AI product can integrate or that all deployment
options are already production-ready. `ROADMAP.md` retains the detailed
implementation checklist; `docs/PRODUCTION_TESTING.md` defines release
evidence and the strict readiness command.

## Current verified position

- Static architecture, security-policy, protocol, signature/evidence,
  SQLite, and PostgreSQL RLS inventory checks pass.
- Rust workspace tests, formatting, and warnings-as-errors Clippy pass.
  The latest CLI input-hardening changes pass all 68 CLI unit tests.
- Encrypted CLI lifecycle, MCP stdio, and fresh-process cross-tool continuity
  pass, including explicitly approved observations and disclosure receipts.
- Those local lifecycle tests now isolate inherited Rembrane configuration,
  selecting development keys and native graph processing instead of ambient
  key references or remote providers. CLI/MCP/continuity also pass with
  deliberately conflicting fixture settings. The REST rerun still fails at
  loopback binding; configuration isolation is not full HTTP runtime evidence.
- CLI portability now has executable round-trip coverage: private plaintext
  JSONL/Markdown/graph exports, encrypted proposal-only JSONL imports with
  preserved project scopes and fresh destination identities, and rejection
  of unsupported scope selectors before I/O. Imports are not trusted memory
  until explicit approval; exports are not project-filtered sharing APIs.
- REST synchronous operations now use bounded blocking workers with
  authentication-before-admission, explicit overload responses, and
  cancellation-safe capacity ownership. No-listener tests cover encrypted
  remember/recall and tenant denial, but real HTTP/provider/load verification
  is still required.
- All MCP tools now preserve the SDK request context while dispatching
  synchronous storage/provider work to process-shared bounded workers.
  Stdio startup and bounded async service constructors isolate provider
  initialization. Actual in-memory SDK tests cover encrypted preference
  continuity and verified per-request proof. Owned/shared remote authorization
  services now isolate synchronous OAuth verification on a separate bounded
  worker budget; the real remote HTTP service and HTTPS/staging tests remain
  required.
- Tenant Tower dispatch now isolates synchronous service selection and provider
  construction on bounded workers. The cache reserves pending capacity but
  releases its global lock during construction, preserving single-flight
  initialization without serializing unrelated tenant lookups. Library tests
  cover panic/cancellation cleanup and overload, not a deployed SDK listener.
- Expired tenant-service cleanup runs outside the global cache lock. The
  remote adapter's 109 passing unit tests include blocked/panicking cleanup,
  concurrent tenant progress, reclaimed capacity, and pending reservation
  preservation. Live provider shutdown and load behavior remain unverified.
- REST and MCP startup now check canonical metadata authority before
  initializing workspace keys or graph clients. Tests reject unknown,
  foreign, and inactive identities without provider calls. MCP also denies
  rotation-blocked startup; the REST invitation/recovery exceptions retain
  empty memory grants. This does not establish live KMS/provider behavior.
- Remote proofs now retain a non-renewable monotonic validity deadline through
  verification, service construction, readiness, and MCP tool admission.
  Session commit rejects elapsed proof and compensates an already initialized
  session. Unit/Tower fixtures do not establish real listener behavior or
  ongoing event-stream expiry/revocation.
- Session bindings now preserve their own non-renewable monotonic deadline.
  Registry tests exercise real expiry and capacity recovery under stale epoch
  time; contract and worker tests prove returned POST/DELETE proofs retain the
  session ceiling without changing signed claims. Actual SDK metadata/streaming
  behavior still needs proof.
- Established-session POST dispatch now retains the registry-authorized
  session identifier and validated HTTP metadata in direct and tenant-selected
  Tower requests. Borrowing and owned/shared fixtures verify it, deny session
  substitution, and keep initialization sessionless. This does not establish
  actual SDK session-manager or listener behavior.
- Session-bound GET now has a separate consuming authorization port and
  owned/shared bounded-worker entrypoints. Direct/tenant Tower fixtures retain
  its exact session, original deadline, and HTTP metadata; tests deny unknown
  sessions and identity/scope substitution, verify unlocked dispatch, and
  reject execution after readiness/factory waits exceed that deadline.
  Both GET modes reject replay explicitly. Actual SDK response delivery and
  live revocation remain unwired and unverified.
- Client DELETE now requires direct/tenant Tower HTTP success before removing
  the local binding. Three response-status matrices cover non-success classes
  and HTTP 200/202/204 retry success across borrowing and owned/shared routes.
  Transport success alone no longer passes as protocol confirmation. Actual SDK
  listener/session-manager confirmation remains required.
- Local session mutation completion now requires an opaque incarnation guard
  captured before dispatch. Two synchronized Tower regressions first reproduced
  a late DELETE/rollback erasing a same-ID/same-claims replacement; guarded
  completion denies it. Three registry regressions cover exact-proof reuse,
  foreign instances, pruning, and repeated completion. This is local registry
  protection, not live SDK cancellation or external-store consistency evidence.
- Anonymous initialization reservations now carry an exact slot identity.
  Two reproductions showed foreign commit/cancel incorrectly consuming a
  different registry's matching counter; both now deny without changing either
  ledger. A third regression distinguishes token equality across instances.
  All 65 application tests and existing remote admission/cancellation fixtures
  pass. This is local capacity isolation, not live SDK resource-cleanup evidence.
- A new response-body guard stops delivery at the earlier original proof/
  controller deadline or explicit sticky revocation. Fourteen new Axum body
  tests cover idle wakeups, per-claim binding, tenant separation, frame/trailer
  races, and cleanup. This is opt-in transport composition, not an already
  wired SDK listener or a live revocation monitor. Both integrations remain
  required before release.
  Shared initialization preserves validated Host/Origin for compensation;
  failed compatibility initialization can roll back only an exact unchanged
  binding after expiry. Actual SDK cache-pruning/late-cleanup races still need
  verification.
- Stateful Tower initialization retains the selected service for late-failure
  compensation instead of asking the factory/cache for it again. A delayed
  fixture prunes and replaces the entry while initialization is running, then
  proves cleanup reaches only the original service. Retained selection checks
  exact authority metadata and uses bounded workers; this is not an actual SDK
  session-manager or live listener proof.
- The PostgreSQL boundary includes a fail-closed runtime-authority guard with
  74 passing adapter unit tests. Its new shared SQL fixtures still require
  live PostgreSQL execution; the concrete database driver remains missing.
- PostgreSQL fixture safety now has 28 passing fake-client guard cases. The
  runner no longer resets existing resources: it requires a private libpq
  service profile, explicit disposable-database authorization, and a read-only
  exact-target/empty-state check. Updated live CI/staging execution is still
  required; guard tests are not database or RLS proof.
- The concrete PostgreSQL runtime gate no longer accepts manifest/source
  regex scaffolding. It requires resolved normal dependencies, compilation
  of the enabled integration target, and separate live execution of the five
  documented pool/repository tests. Its 37 fake-Cargo cases verify refusal
  and admission only. The real checker still fails because the driver is absent.
- The full test run cannot complete in the current environment: the REST
  process is denied permission to bind `127.0.0.1:18787`.
- Direct Git commits are available again. Verified slices are recorded
  locally; release evidence still requires an exact clean release candidate.
- The cached, locked Cargo dependency graph builds offline. An approved HTTP
  registry probe succeeded, but Cargo's attempted fetch of the missing
  Streamable HTTP dependencies still failed DNS resolution. This is not proof
  of a global crates.io outage or of complete dependency access. The transport
  feature was reverted after the failed fetch, leaving the existing build
  intact; a concrete PostgreSQL driver is also absent from the local cache.
- A fresh isolated official-transport dependency probe fails offline because
  `async-trait` cannot be resolved from the cache. A bounded online retry still
  fails resolving `index.crates.io`. The repository dependency graph remains
  unchanged; the failed probe is not SDK compilation or live listener evidence.
- The PostgreSQL client is unavailable here, and access to the Docker daemon
  socket is denied. Live database fixtures and container verification are not
  covered by the passing local tests.

Passing local tests is not independent security approval, live cloud-provider
conformance, a deployed PostgreSQL proof, or production release approval.

## Immediate execution queue

1. Wire the verified remote MCP session/transport boundary into the actual
   official SDK listener. Retain explicit replay rejection until isolation
   is verified. Resolve and lock the official MCP
   transport dependencies, then wire the actual remote service and stream
   revocation authorities behind that boundary. Do not enable an unbuildable
   feature or count scaffolding as a supported integration.
2. Implement the concrete PostgreSQL driver and pool, then run the shared
   runtime-authority fixtures and pooled two-tenant lifecycle tests against a
   dedicated disposable database.
3. Run the complete HTTP and container test suites in a capable staging
   environment, followed by concurrency, performance, and recovery drills.
4. Gather independent provider/KMS evidence and schedule independent security
   review; freeze a clean candidate before collecting revision-bound approval.
5. Clear the strict release gate, test published installation artifacts,
   and complete a controlled pilot before production promotion.

Security fixes that can be built and verified locally continue while runtime
dependencies are unavailable. They do not replace the runtime exit criteria.
Roadmap checkboxes are updated only for implemented and verified slices, with
live or independently reviewed evidence tracked separately.

## Completion checkpoints

| Checkpoint | Current position | Completion evidence |
| --- | --- | --- |
| Local development baseline | Core tests pass; runtime integrations remain incomplete | Both concrete runtime integrations build and their integration tests pass |
| Ready for production end-to-end testing | Not yet | Installable candidate, working HTTP/SDK listener and PostgreSQL, disposable staging services, and executable test/runbook coverage |
| End-to-end testing complete | Not yet | HTTP, isolation, load, outage, recovery, rotation, deletion, and deployment drills pass with retained results |
| Release candidate approved | Not yet | Revision-bound provider evidence, independent security approval, and strict readiness passing |
| First supported production release | Not yet | Clean-system installation/upgrade tests and controlled pilot pass; supported scope and rollback documented |

Development continues with reviewable local commits and no automatic push.
The next code checkpoint is a verified remote session-transport slice, not a
production-release claim. Staging access, missing dependency resolution, real
provider credentials, and an independent reviewer are external capabilities;
repository changes alone cannot supply their evidence.

## Scope and sequencing

The initial production target is the documented personal, development, and
travel memory infrastructure with tenant isolation, controlled sharing,
encrypted storage, CLI/SDK access, and supported MCP/REST integrations.
Provider and deployment claims must match verified evidence. Managed
onboarding, a polished non-technical desktop app, and integrations with
closed third-party bots are separate deliverables, not implied by a backend
release.

No existing strict release gate is waived by this plan.

### 1. Close concrete runtime gaps

- [ ] Wire the official pinned Rust MCP SDK Streamable HTTP service through
  the existing OAuth, tenant, session, and request-authorization boundaries.
- [x] Keep MCP tool/provider work and async service initialization off executor
  threads, with bounded admission and capacity held through actual completion
  after cancellation.
- [x] Isolate synchronous OAuth verification on bounded workers in the
  owned/shared remote authorization-service async entrypoints.
- [x] Isolate tenant service factories on a separate bounded worker budget and
  release the global service-cache lock during per-identity construction.
- [ ] Exercise that boundary with the actual official SDK remote listener
  and real HTTPS introspection; do not route blocking verifier clients through
  the lower-level borrowing compatibility helpers on an executor.
- [ ] Prove expiry/revocation behavior for queued SDK tools and already opened
  streams in that listener; dispatch admission alone is insufficient.
  - [x] Implement and test the response-delivery guard independently of the
    unavailable listener feature.
  - [ ] Connect the guard to real revocation authorities and verify it on
    actual SDK responses, with bounded stream/monitor lifetimes.
- [ ] Enable its actual transport feature and resolve/build the complete
  locked dependency graph; a protocol adapter alone is insufficient.
- [ ] Implement a concrete PostgreSQL driver, pool, and runtime repository
  over the existing tenant facade and migrations.
- [ ] Prove real pooled-connection tenant binding/reset, atomic mutations,
  rollback, cancellation, and cross-tenant denial against PostgreSQL.

Exit: both runtime wiring checks pass and executable integration tests cover
their authorization and persistence boundaries. Prioritize these gaps over
adding new domains or optional integrations.

### 2. Establish the executable staging baseline

- [ ] Run REST/Postman and authenticated remote MCP tests in an environment
  that permits loopback binding and dependency resolution.
- [ ] Verify container build, non-root/read-only deployment, persistent
  encrypted state, initialization, upgrade, and restart behavior.
- [ ] Exercise multi-user concurrency, stale writers, lock contention,
  bounded requests, cancellation, retries, and resource exhaustion.
- [ ] Perform backup/restore, key rotation/recovery, deletion/retention, and
  provider outage/recovery drills using disposable data.
- [ ] Record repeatable read/write/search load measurements and the supported
  operating envelope; do not claim unmeasured performance targets.

Exit: the complete test suite and deployment/recovery drills pass without
silently skipped required gates.

### 3. Gather real provider and key-management evidence

- [ ] Run disposable customer-KMS conformance for the required AWS, Azure,
  and GCP evidence set.
- [ ] Retain passing protocol evidence for two independent implementations,
  including an externally maintained implementation with signed provenance.
- [ ] Run the oldest/newest supported-minor compatibility matrix and
  unsupported-major rejection tests.
- [ ] Bind evidence to the exact clean release-candidate revision and
  compatibility artifact inventory.

Exit: the existing evidence verifiers accept the retained artifacts.
Synthetic fixtures and locally generated signatures must not be presented
as external-provider validation.

### 4. Freeze and independently review the release candidate

- [ ] Commit each verified slice in reviewable units and prepare release
  evidence only from a clean, frozen release candidate.
- [ ] Freeze supported integrations, protocol artifacts, and migration notes.
- [ ] Obtain an independent review of authentication, tenant isolation,
  encryption/key handling, provider trust, deletion, backup, and recovery.
- [ ] Resolve findings or obtain documented owner acceptance of eligible
  risks; retain an approving signed review for the candidate revision.
- [ ] Run strict production readiness with no missing gates and retain the
  evidence and exit status.

Exit: `scripts/check-production-readiness.sh --strict` passes for the reviewed
candidate. Material code changes after review require corresponding evidence
and review updates.

### 5. Release and controlled adoption

- [ ] Produce pinned release artifacts, installation/upgrade instructions,
  support limitations, operational runbooks, and rollback instructions.
- [ ] Test installation from release artifacts on clean supported systems.
- [ ] Run a limited real-user pilot, review failures and privacy expectations,
  then promote the same verified scope to the first production release.

Closed bots, Apple messaging accounts, and other platform integrations need
their own access and support proof. An unavailable integration must be
explicitly excluded, not marketed as automatic universal compatibility.

## Timing

A preliminary planning range is **6–10+ calendar weeks for the first supported
infrastructure release**, assuming runtime/dependency access, disposable
staging services, external-provider cooperation, and an independent reviewer
are available. This is an uncertain estimate, not a release commitment.

The estimate does not include building every proposed hosted/desktop
experience or integrating every third-party assistant. Time waiting for
permissions, cloud services, an external maintainer, or review scheduling can
extend it materially.

Replace this range with a dated forecast after milestones 1 and 2 have
executable results and the external review is scheduled. Report milestone
exits and remaining gates, not a percentage inferred from roadmap checkbox
counts. Production completion means verified release criteria, not simply
running out of development tasks.

There is no defensible fixed release date yet. Development can proceed
autonomously within the repository, but an unavailable staging capability or
an independent reviewer cannot be substituted with local mocks or a maintainer
self-approval. A review finding or failed recovery drill can add another
implementation-and-verification cycle.
