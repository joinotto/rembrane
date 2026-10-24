# Testing Rembrane

Rembrane is pre-alpha. Test only with disposable data and development keys.

## Prerequisites

- Rust 1.88 with `rustfmt` and `clippy`
- SQLite 3
- Node.js
- `jq`
- Postman CLI

Run every check:

```text
./scripts/test-all.sh
```

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
6. REST authentication and tenant-isolation checks through Postman.

Provider authors should also run the shared Rust conformance harness against a
disposable provider tenant:

```text
verify_semantic_provider(&mut provider, "unique-test-namespace")
```

Inspect the exact compatibility registry compiled into the local CLI:

```sh
target/debug/rembrane providers list | jq .
```

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
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_WORKSPACE_KEY_HEX="$(openssl rand -hex 32)"
export REMBRANE_API_TOKEN="$(openssl rand -hex 32)"
```

Do not put real keys directly in shell history, command arguments, committed
configuration, screenshots, logs, or issue reports.

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
