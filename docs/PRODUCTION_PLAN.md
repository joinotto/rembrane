# First production release plan

Status assessment: 2026-10-26. Rembrane remains pre-alpha.

This is the execution plan for the first supported infrastructure release,
not a promise that every AI product can integrate or that all deployment
options are already production-ready. `ROADMAP.md` retains the detailed
implementation checklist; `docs/PRODUCTION_TESTING.md` defines release
evidence and the strict readiness command.

## Current verified position

- Static architecture, security-policy, protocol, signature/evidence,
  SQLite, and PostgreSQL RLS inventory checks pass.
- Rust workspace tests, formatting, and warnings-as-errors Clippy pass.
  The latest CLI input-hardening change also passes all 63 CLI unit tests.
- Encrypted CLI lifecycle, MCP stdio, and fresh-process cross-tool continuity
  pass, including explicitly approved observations and disclosure receipts.
- The PostgreSQL boundary includes a fail-closed runtime-authority guard with
  74 passing adapter unit tests. Its new shared SQL fixtures still require
  live PostgreSQL execution; the concrete database driver remains missing.
- The full test run cannot complete in the current environment: the REST
  process is denied permission to bind `127.0.0.1:18787`.
- Direct Git commits are available again. Verified slices are recorded
  locally; release evidence still requires an exact clean release candidate.
- `index.crates.io` still fails DNS resolution in this environment. The
  missing Streamable HTTP support dependencies and a concrete PostgreSQL
  driver were not found in the local source cache.

Passing local tests is not independent security approval, live cloud-provider
conformance, a deployed PostgreSQL proof, or production release approval.

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
