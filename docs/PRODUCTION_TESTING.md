# Production testing

Run the complete release-candidate gate with:

```sh
REMBRANE_POSTGRES_TEST_SERVICE_FILE=/secure/rembrane-fixture.conf \
REMBRANE_POSTGRES_RUNTIME_URL_FILE=/secure/rembrane-runtime-url \
REMBRANE_POSTGRES_TEST_DATABASE=rembrane_test_release \
REMBRANE_POSTGRES_TEST_CONFIRM=disposable-empty-database \
REMBRANE_SECURITY_REVIEW_BUNDLE=/secure/review-bundle \
REMBRANE_SECURITY_REVIEW_PUBLIC_KEY=/secure/reviewer-public.pem \
REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY=/secure/kms-provider-evidence \
REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY=/secure/memory-provider-evidence \
REMBRANE_MEMORY_PROVIDER_EXTERNAL_PUBLIC_KEY=/secure/external-provider-maintainer.pem \
  ./scripts/check-production-readiness.sh --strict
```

For CI, installers, bots, and hosted control planes, request a single
machine-readable result on stdout:

```sh
./scripts/check-production-readiness.sh --strict --json
```

Progress and diagnostics remain on stderr. The stdout document validates
against `spec/production-readiness.schema.json`; `schemaVersion` is currently
`1`, `ready: true` requires an empty `missing` collection, and strict mode
still exits non-zero when any required gate is unavailable.

Strict mode requires dependency resolution, Rust and Postman tests, a live
fresh disposable PostgreSQL database dedicated to the RLS fixture, and a working
Docker daemon. The HTTP suites require permission to bind an ephemeral
loopback socket. It also verifies the independently signed security-review
bundle and exact AWS/Azure/GCP customer-KMS evidence set. It fails rather than
silently skipping unavailable gates. It also requires the exact
Memory Provider release-evidence directory containing two independent passing
providers, at least one externally maintained provider, and mixed-version
compatibility evidence. Both the independent review and provider evidence must
name the exact clean repository `HEAD`; evidence for an older or dirty source
tree is rejected. The external provider result must carry a detached Ed25519
signature valid under the separately supplied maintainer trust anchor; an
`"external"` label alone is not evidence. A structurally valid signed review with
`changes_required` remains inspectable, but strict readiness accepts only
`approved` or `approved_with_accepted_risks`.

`available` (or `--available`) mode runs every usable gate and reports each
missing prerequisite separately. It distinguishes Cargo dependency resolution,
Postman, loopback binding, the PostgreSQL client, private fixture service
profile and explicit disposable-database authorization, and the Docker CLI
and daemon. Restricted sandboxes therefore identify the exact unavailable
capability instead of hiding it behind one grouped suite label. Available mode
is suitable during offline development but is not production approval.

## Safe PostgreSQL fixture setup

Never point this test at an application database or a shared production cluster.
Use an isolated disposable PostgreSQL instance under exclusive operator control,
with a newly created database named `rembrane_test_<lowercase_suffix>`. The suite
creates cluster-wide test roles and intentionally leaves its fixture state in
place for inspection. Use a fresh instance for the next run; cleanup is the
operator's responsibility, not an automatic drop/reset of existing resources.

Supply a caller-owned regular libpq service file using an absolute path and
permissions `0600` (or `0400`). Symlinks and non-private files are rejected.
Keep the profile under exclusive control throughout the run. Example structure
(replace placeholders privately; never commit real credentials):

```ini
[rembrane_fixture]
host=127.0.0.1
port=5432
user=<disposable-instance-administrator>
password=<disposable-instance-password>
dbname=rembrane_test_release
connect_timeout=10
```

The runner uses libpq's service configuration, not the application's
`REMBRANE_POSTGRES_URL`. Credentials are not passed in process arguments; this
is local plaintext configuration, not encrypted secret storage. Host/account
security and production TLS policy remain operator responsibilities. Node 22
and `psql` are required. User `psql` startup files and password prompts are
disabled; failed command output is redacted.

Before any migration, a read-only probe must match the exact expected database,
find no user relations/functions/types, no additional user schemas, event
triggers, large objects, foreign servers, publications, additional extensions
(other than stock `plpgsql`), or pre-existing fixture role. Any mismatch fails
without mutation. This prevents
accidental reuse; it cannot defeat concurrent administrators changing the
target after the probe. The guard's fake-client tests are not a live SQL/RLS
proof; the updated PostgreSQL CI job and staging suite must still execute.

## Concrete PostgreSQL runtime gate

The live `psql` RLS suite is separate from the Rust runtime driver proof.
Neither a dependency name nor a public pool struct establishes a working
repository. The checker has two explicit modes:

```sh
./scripts/check-postgres-runtime-adapter.sh --build
./scripts/check-postgres-runtime-adapter.sh --live
```

Build mode inspects locked offline Cargo metadata for a resolved normal driver
dependency and an enabled `postgres_runtime` integration target, then compiles
that exact target. It does not claim database connectivity. Live mode additionally
requires disposable-database authorization and private administrator/runtime
configuration. Strict readiness requires both stages, not build mode alone.

`REMBRANE_POSTGRES_RUNTIME_URL_FILE` must be a separate private caller-owned
regular file containing the restricted runtime connection URL. It is not a
libpq service file. The integration suite must resolve it through the existing
`SecretReference::file` / `resolve_postgres_connection` boundary, respecting
the declared transport policy. The administrator's libpq service profile stays
in `REMBRANE_POSTGRES_TEST_SERVICE_FILE`. Runtime requests must never borrow
administrator credentials. Both configurations are plaintext local secrets,
not commit-worthy examples.

The required root-level integration tests in `postgres_runtime` are:

| Exact test name | Required live behavior |
| --- | --- |
| `runtime_pool_two_tenant_lifecycle` | Real pool/repository encrypted lifecycle for two tenants; deny cross-tenant access. |
| `runtime_pool_connection_reset_after_rollback_and_error` | Reuse real pooled connections without leaking tenant settings after success, rollback, or error. |
| `runtime_pool_rejects_unsafe_authority` | Reject unsafe actual server roles/authority before tenant data access. |
| `runtime_pool_atomicity_and_cancellation` | Prove atomic commit/rollback and safe reuse after cancellation/abandoned operations. |
| `runtime_pool_redacts_driver_errors` | Exercise real driver failures without leaking credentials, SQL parameters, or tenant data through application errors. |

Run against the explicitly named isolated fixture database. Each test must
verify the actual database before mutation, check live server authority, and
fail when prerequisites are missing. An early successful return, a mock
connection, or ignored-only execution is not acceptable live evidence.
The checker executes each exact test with ignored tests enabled, demands exactly
one pass and zero ignored/failed tests, and redacts captured diagnostics.
Maintainer review and independent security review must verify that the test
bodies genuinely cover the matrix; execution counts alone cannot detect a
no-op or fabricated test implementation.

The current repository has no concrete driver or this live integration target.
The gate remains failing intentionally. Its 37 fake-Cargo regression cases
verify gate behavior, not Rust compilation or PostgreSQL behavior.

Platform credentials and real WhatsApp/Apple integration accounts remain
human or external-system release gates and cannot be self-certified by this
script. The script can verify retained security-review and customer-KMS
evidence and validate Memory Provider release evidence, but it cannot create
that independent evidence itself.

After independently running both providers and the mixed-version matrix,
assemble the retained Memory Provider evidence without supplying credentials:

```sh
node scripts/package-memory-provider-release-evidence.mjs \
  /secure/memory-provider-evidence \
  "$(git rev-parse HEAD)" \
  2026-10-25T12:00:00Z \
  /secure/runs/mixed-version.json \
  /secure/runs/provider-a.json \
  in-repository rembrane-maintainers <provider-a-source-revision> \
  /secure/runs/provider-b.json \
  /secure/runs/provider-b.provenance.json \
  /secure/runs/provider-b.provenance.json.sig \
  /secure/external-provider-maintainer.pem
```

Use the actual UTC packaging time. The destination must not exist. The tool
accepts only bounded regular input files, creates an owner-only directory,
copies the reviewed compatibility lock and migration contract, verifies the
complete result, and removes the new directory if verification fails. It
never reads provider tokens or cloud credentials.

The external maintainer creates the provenance JSON, signs those exact bytes,
and supplies both files. The signed statement—not the release packager—binds
their maintainer ID and source revision to the conformance-result digest.

They can generate the canonical statement without exposing credentials:

```sh
node scripts/generate-memory-provider-external-provenance.mjs \
  provider-b.json \
  <external-maintainer-id> \
  <provider-b-source-revision> \
  <current-UTC-time> \
  > provider-b.provenance.json

chmod 600 maintainer-private.pem
node scripts/sign-ed25519-document.mjs \
  provider-b.provenance.json \
  maintainer-private.pem \
  provider-b.provenance.json.sig
```

The signer rejects symbolic, permissive, oversized, or non-Ed25519 private
keys, opens the key without following links, and zeros its input buffer after
constructing the signing key. The private key remains with the external
maintainer. Transfer only the
result, provenance statement, signature, and independently distributed public
key.
