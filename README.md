# Rembrane

**Your memory across every connected AI.**

Rembrane is an open-source, user-owned continuity and memory infrastructure for AI assistants, coding tools, applications, bots, and agents.

> [!IMPORTANT]
> Rembrane is in pre-alpha. The architecture and protocol are being defined; no production release exists yet.

## Product promise

Record relevant identity, preferences, work, decisions, and active context once; reuse them safely across authorized AI tools without repeated explanation.

Initial domains:

- Personal memory
- Development memory by project
- Travel memory

Deployment options:

- Managed service
- Non-technical desktop/local application
- Docker/self-hosted server
- Customer cloud or Kubernetes
- Strict-E2EE local/customer-controlled gateway

Rembrane supports personal and shared organizational workspaces, provider-independent configuration, bring-your-own credentials, and replaceable memory, graph, vector, database, model, and storage providers.

## Architecture direction

```text
Rust portable core
├── REST and MCP
├── setup CLI
├── local E2EE gateway
├── authorization
├── synchronization
└── provider orchestration

Existing systems
├── Mem0 / Hindsight / Cognee
├── Graphiti
├── PostgreSQL / pgvector / Qdrant
├── OpenMLS / libsodium-compatible crypto / SQLCipher
└── Cloudflare or customer-selected infrastructure
```

The platform owns identity, workspaces, encryption orchestration, canonical events, provenance, permissions, context compilation, and portability. Existing systems provide specialized memory extraction, graph construction, retrieval, storage, and cryptography.

## Documents

- [Portable Memory Provider Client](docs/MEMORY_PROVIDER_CLIENT.md)
- [Product Requirements and Architecture](docs/PRODUCT_REQUIREMENTS_AND_ARCHITECTURE.md)
- [Rust Architecture Research](docs/RUST_ARCHITECTURE_RESEARCH.md)
- [Bot and Platform Integration Architecture](docs/BOT_AND_PLATFORM_INTEGRATION_ARCHITECTURE.md)
- [Support and Compatibility Policy](docs/SUPPORT_POLICY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Recovery Model](docs/RECOVERY_MODEL.md)
- [Secret Resolution](docs/SECRET_RESOLUTION.md)
- [Architecture Decision Records](docs/adr/README.md)
- [Roadmap](ROADMAP.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Testing](docs/TESTING.md)
- [Local Alpha Acceptance Contract](docs/LOCAL_ALPHA_ACCEPTANCE.md)

## Current key decisions

- Rust is the authoritative portable backend and local core.
- PostgreSQL is the default canonical hosted store.
- Graphiti is the initial temporal knowledge-graph engine.
- Mem0 OSS, Hindsight, Cognee, and a native baseline will be benchmarked.
- Cloudflare is a reference hosted edge/synchronization platform, not mandatory.
- Self-hosted credentials stay inside the operator’s environment.
- Strict E2EE performs search and memory processing on authorized devices or customer-controlled gateways.
- Non-technical users receive managed or desktop onboarding with plain-language permissions.
- Bot compatibility uses verified tiers: native protocol, MCP/tool, user-controlled gateway, share extension, or import/export.
- Existing closed iMessage or WhatsApp bot conversations require vendor cooperation or an explicit user-controlled fallback; channel access alone cannot inject memory.

## Project status

The first development milestone is a secure vertical slice:

```text
store a confirmed preference
→ retrieve it from a second authorized agent
→ record exactly what was disclosed
→ correct or delete it
→ prevent access from another tenant
```

See the [roadmap](ROADMAP.md) for sequencing. Do not use Rembrane for production or sensitive data until the security model, cryptographic implementation, and tenant-isolation tests are complete.

## Development

Prerequisite: Rust 1.88 or newer with `rustfmt` and `clippy`.

```text
./scripts/check-local-alpha.sh
./scripts/check-architecture.sh
./scripts/check-sensitive-files.sh
./scripts/test-static.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p rembrane-cli -- demo
cargo run -p rembrane-cli -- init \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_personal

# After each person initializes a personal identity in the same deployment:
cargo run -p rembrane-cli -- workspace create-shared \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_team

cargo run -p rembrane-cli -- invitation create \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_team \
  --invitation invite_01 \
  --subject principal_teammate \
  --role member \
  --ttl-seconds 86400 \
  --request request_invite_01

cargo run -p rembrane-cli -- invitation accept \
  --database .rembrane/rembrane.db \
  --principal principal_teammate \
  --workspace workspace_team \
  --invitation invite_01 \
  --request request_accept_01

cargo run -p rembrane-cli -- invitation list \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_team \
  --status accepted \
  --limit 50

export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_WORKSPACE_KEY_HEX=<64-hex-character-development-key>

cargo run -p rembrane-cli -- remember \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_personal \
  --content "Call me Hippo"

cargo run -p rembrane-cli -- recall \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_personal \
  --client assistant_local \
  --purpose personalize-assistant \
  --query "What should I call the user?"

cargo run -p rembrane-cli -- correct \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_personal \
  --memory <memory-id> \
  --version 1 \
  --content "Call me Captain Hippo"

cargo run -p rembrane-cli -- forget \
  --database .rembrane/rembrane.db \
  --principal principal_local \
  --workspace workspace_personal \
  --memory <memory-id> \
  --version 2
```

The demo stores a confirmed preference, resolves it for a second authorized assistant, and prints the context-pack and disclosure-receipt identifiers.

The current vertical slice persists local identities, workspaces, encrypted
memories, activity checkpoints, audit events, and disclosure receipts in
SQLite. It exposes a local stdio MCP server and bearer-authenticated REST
context retrieval. Production customer-KMS integration, the Rust PostgreSQL
repository adapter, stable remote OAuth MCP, and additional third-party agent
adapters remain roadmap work.

The environment-key flow is for development testing only. Shell history must
never contain the key value. On macOS, Rembrane can resolve the workspace key
from the current user's Keychain without exporting the key:

```text
export REMBRANE_KEY_PROVIDER=macos-keychain
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_KEYCHAIN_SERVICE=org.rembrane.workspace
export REMBRANE_KEYCHAIN_ACCOUNT="$REMBRANE_WORKSPACE_ID"
export REMBRANE_KEYCHAIN_HISTORICAL_KEYS=

openssl rand -hex 32 | /usr/bin/security add-generic-password \
  -U -s "$REMBRANE_KEYCHAIN_SERVICE" -a "$REMBRANE_KEYCHAIN_ACCOUNT" -w
```

The final `-w` prompts through standard input, so key material is not placed in
the process arguments. Do not use `-A`; retain Keychain access control.

On Linux desktops with Secret Service and `/usr/bin/secret-tool`, store the
hex key through standard input and configure lookup metadata only:

```text
export REMBRANE_KEY_PROVIDER=linux-secret-service
export REMBRANE_WORKSPACE_KEY_ID=local-key-v1
export REMBRANE_SECRET_SERVICE_SERVICE=org.rembrane.workspace
export REMBRANE_SECRET_SERVICE_ACCOUNT="$REMBRANE_WORKSPACE_ID:key_v1"
export REMBRANE_SECRET_SERVICE_HISTORICAL_KEYS=

openssl rand -hex 32 | /usr/bin/secret-tool store \
  --label="Rembrane workspace key" \
  rembrane-service "$REMBRANE_SECRET_SERVICE_SERVICE" \
  rembrane-account "$REMBRANE_SECRET_SERVICE_ACCOUNT" \
  rembrane-key-id "$REMBRANE_WORKSPACE_KEY_ID"
```

The desktop session must provide an unlocked Secret Service collection. Key
output is captured into zeroizing process memory and never placed in command
arguments. Lookup binds service, account, and expected key ID so historical
generations cannot resolve through a reused account label.

On Windows, a workspace key can be protected for the current signed-in user
with DPAPI. Run this in Windows PowerShell; the raw key is generated and
cleared inside the process and is never supplied as a command argument:

```powershell
$env:REMBRANE_KEY_PROVIDER = "windows-dpapi"
$env:REMBRANE_WORKSPACE_KEY_ID = "local-key-v1"
$env:REMBRANE_DPAPI_BLOB_PATH = "$env:LOCALAPPDATA\Rembrane\local-key-v1.dpapi"
$env:REMBRANE_DPAPI_HISTORICAL_KEYS = ""
$directory = Split-Path -Parent $env:REMBRANE_DPAPI_BLOB_PATH
[IO.Directory]::CreateDirectory($directory) | Out-Null
[byte[]]$key = New-Object byte[] 32
$rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($key)
[byte[]]$entropy = [Text.Encoding]::UTF8.GetBytes($env:REMBRANE_WORKSPACE_KEY_ID)
try {
  [byte[]]$blob = [Security.Cryptography.ProtectedData]::Protect(
    $key, $entropy,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
  )
  [IO.File]::WriteAllBytes($env:REMBRANE_DPAPI_BLOB_PATH, $blob)
} finally {
  if ($null -ne $blob) { [Array]::Clear($blob, 0, $blob.Length) }
  [Array]::Clear($key, 0, $key.Length)
  [Array]::Clear($entropy, 0, $entropy.Length)
  $rng.Dispose()
}
```

The resolver uses the fixed system Windows PowerShell executable, passes only
the protected blob path and key ID, binds the key ID as DPAPI entropy, and
zeroizes captured output. A blob is user- and machine-bound by DPAPI; preserve
a separately protected recovery copy before relying on it. HSM and direct
cloud-specific customer-KMS sidecars remain roadmap work. The vendor-neutral
operation boundary and deployment contract are documented in
`docs/CUSTOMER_KMS.md`.

A customer-controlled Key Provider Protocol sidecar can keep raw workspace
keys outside the Rembrane process:

```text
export REMBRANE_KEY_PROVIDER=http
export REMBRANE_KEY_PROVIDER_BASE_URL=https://keys.example
export REMBRANE_KEY_PROVIDER_TOKEN='resolve-from-your-secret-manager'
export REMBRANE_KEY_PROVIDER_REQUIRE_HISTORICAL_KEYS=true
```

Exact loopback HTTP is accepted for a same-machine sidecar; non-loopback
deployments require HTTPS. The client disables redirects and environment
proxies, bounds responses, authenticates every operation, and negotiates
protocol, algorithm, plaintext size, and historical-key support before use.
Applications may instead construct `KeyProviderHttpConfig` and pass it to
`ConfiguredRecordCipher::from_http_config`. This supports credentials resolved
from any application-owned keychain, vault, cloud secret manager, or injected
file without copying them into fixed Rembrane environment variables. The
consumed configuration and transport zeroize the bearer credential on both
success and failure paths.

After rotating to a new active item, retain old items only while historical
ciphertext still references them and list their metadata as comma-separated
`key_id=account` entries:

```text
export REMBRANE_WORKSPACE_KEY_ID=local-key-v2
export REMBRANE_KEYCHAIN_ACCOUNT="$REMBRANE_WORKSPACE_ID:key_v2"
export REMBRANE_KEYCHAIN_HISTORICAL_KEYS="local-key-v1=$REMBRANE_WORKSPACE_ID"
```

New records use `local-key-v2`; records whose envelope names `local-key-v1`
are resolved through the historical account. Key bytes remain in Keychain.

Generate a secret-safe stdio MCP configuration for a supported coding client:

```text
target/debug/rembrane mcp-config clients

target/debug/rembrane mcp-config \
  --client codex \
  --server-binary "$PWD/target/debug/rembrane-mcp" \
  --key-provider macos-keychain

target/debug/rembrane mcp-config \
  --client claude-code \
  --server-binary "$PWD/target/debug/rembrane-mcp"

target/debug/rembrane mcp-config \
  --client gemini-cli \
  --server-binary "$PWD/target/debug/rembrane-mcp"

target/debug/rembrane mcp-config \
  --client opencode \
  --server-binary "$PWD/target/debug/rembrane-mcp"

target/debug/rembrane mcp-config \
  --client generic \
  --server-binary "$PWD/target/debug/rembrane-mcp"
```

Generated MCP configurations pass only credential locators such as
`REMBRANE_WORKSPACE_KEY_REFERENCE` or
`REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE`. Point these at protected files or
another deployment-owned resolver; generated client configuration never asks
the launcher to serialize raw key or bearer-token values.

`mcp-config clients` returns a schema-versioned machine-readable catalog of
every supported client, its configuration format, and whether environment
references are rendered as placeholders, inherited through an allowlist, or
inherited from the launcher process. The portable contract is published as
`spec/mcp-client-catalog.schema.json`.

Zed does not interpolate environment-variable placeholders in its settings
file. Its generated entry therefore leaves `env` empty and inherits Rembrane
configuration from the Zed process environment. Start Zed from a configured
shell or arrange those non-secret settings and credential references through
the operating system's application environment; do not paste raw keys into
Zed settings.

Inspect the compatibility evidence embedded in this CLI build:

```sh
target/debug/rembrane providers list | jq .
```

Run the shared compatibility suite against an adapter installed in the CLI:

```sh
target/debug/rembrane providers test \
  --provider rembrane.native \
  --namespace local-check | jq .
```

The generated configuration references protected environment-variable names;
it never prints their values. The generic output follows the versioned
`spec/stdio-connection-manifest.schema.json` contract for other apps, bots,
launchers, and agent platforms.

The local REST server additionally requires `REMBRANE_DATABASE`,
`REMBRANE_PRINCIPAL_ID`, `REMBRANE_WORKSPACE_ID`, `REMBRANE_CLIENT_ID`, and
`REMBRANE_API_TOKEN`. It listens on `127.0.0.1:8787` by default. Non-loopback
HTTP is rejected unless explicitly enabled for operation behind a trusted TLS
terminator. For outbound-only self-hosted public connectivity, see
`docs/CLOUDFLARE_DEPLOYMENT.md`.

### Self-host with Docker

Copy `.env.example` to `.env`, fill the required non-secret identifiers, and
create mode-restricted secret files:

```text
install -m 600 /dev/null .rembrane-workspace-key
install -m 600 /dev/null .rembrane-api-token
openssl rand -hex 32 > .rembrane-workspace-key
openssl rand -hex 32 > .rembrane-api-token
export REMBRANE_WORKSPACE_KEY_FILE="$PWD/.rembrane-workspace-key"
export REMBRANE_API_TOKEN_FILE="$PWD/.rembrane-api-token"
docker compose up --build
```

The container initializes the requested personal workspace idempotently and
stores its encrypted SQLite database in the `rembrane-data` volume. The
published API remains bound to `127.0.0.1`; place authenticated TLS
termination in front of it before allowing remote access. Compose mounts the
workspace key and API token as owner-only files rather than interpolating
their values into container environment metadata. The local file-backed key
mode is for development and single-node self-hosting; production deployments
should use an OS keychain or customer-controlled key provider. The service
root filesystem is read-only; only the encrypted data volume and bounded
temporary filesystems remain writable. At startup, mounted Compose secrets
are copied into a private runtime tmpfs with enforced owner-only permissions
before the service drops root privileges.

## Contributing

Rembrane is being built in public. Start with [CONTRIBUTING.md](CONTRIBUTING.md), read the [support policy](docs/SUPPORT_POLICY.md), and discuss substantial protocol or security changes before implementing them.

## License

Licensed under the Apache License, Version 2.0.
