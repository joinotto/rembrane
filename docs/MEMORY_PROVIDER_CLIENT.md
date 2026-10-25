# Portable Memory Provider client

Rembrane can use any service implementing Memory Provider Protocol `0.1`.
The configured Rust adapter performs public discovery, validates the complete
operation registry, negotiates required capabilities and privacy mode, and
then sends only capability-checked requests.

## Configuration

Set these values through the process environment or the runtime's secret
injection mechanism:

| Variable | Required | Meaning |
| --- | --- | --- |
| `REMBRANE_MEMORY_PROVIDER` | No | Provider transport. Defaults to `http`. |
| `REMBRANE_MEMORY_PROVIDER_BASE_URL` | Yes | HTTPS origin, or exact loopback HTTP for local development. |
| `REMBRANE_MEMORY_PROVIDER_TOKEN` | Conditional | Default environment source for the OAuth access token or provider-issued bearer credential. |
| `REMBRANE_MEMORY_PROVIDER_TOKEN_REFERENCE` | Conditional | Optional `env:VARIABLE` or protected `file:path` locator. When absent, `REMBRANE_MEMORY_PROVIDER_TOKEN` is used. |
| `REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX` | No | Diagnostic prefix containing 8–64 URL-safe characters. |

Exactly one resolvable credential source is required. Do not commit tokens to
`.env` files, Compose manifests, shell profiles, or application configuration.
Inject them from an OS keychain, container secret, Kubernetes Secret, systemd
credential, customer secret manager, or equivalent deployment-owned facility.
The environment-selected adapter resolves local locators before construction,
keeps the loaded token in zeroizing configuration and transport storage, and
never sends it to the public discovery endpoint. An `external:provider:key`
locator fails closed in this standalone path; applications needing a cloud
vault supply their own `SecretResolver` through a validated provider profile.

Applications that already own configuration and secret resolution can avoid
fixed environment-variable names:

```rust
use rembrane_memory_provider_configured::{
    ConfiguredMemoryProvider, MemoryProviderHttpConfig,
};

let config = MemoryProviderHttpConfig::new_with_secret(provider_url, resolved_token)
    .with_request_prefix("my-agent-01");
let provider = ConfiguredMemoryProvider::from_http_config(config, &policy)?;
```

`MemoryProviderHttpConfig` is consumed during construction and intentionally
does not implement cloning, debug formatting, or serialization. Here
`resolved_token` is a `Zeroizing<String>` obtained from the calling
application's OS keychain, customer vault, cloud secret manager, container
secret, or any other private mechanism.

The base URL must be an origin without embedded credentials, paths, query
parameters, or fragments. Remote plaintext HTTP is rejected. Loopback HTTP is
accepted only for literal `127.0.0.1` or `::1`. Hostnames such as `localhost`
are rejected because local name resolution can be remapped.

## Connection policy

The application supplies a `MemoryProviderPolicy` describing:

- the minimum protocol version;
- the HTTPS transport;
- every capability the application needs;
- acceptable privacy modes;
- minimum context, event, and sync limits.

Connection fails closed when discovery does not satisfy that policy or when
an advertised operation has a non-canonical OAuth scope, method, or path.
Workspace, subject, actor, and client identity are never accepted in portable
operation payloads; the provider derives them from authentication.

`ConfiguredMemoryProvider` exposes typed context, question, proposal, event,
checkpoint, disclosure, lifecycle, and synchronization methods. Every method
creates its request through the negotiated connection before transport.

## Provider requirements

A compatible provider must:

1. Serve `/.well-known/ai-memory` without requiring credentials.
2. Require the exact narrow OAuth scope advertised for each protected route.
3. Echo `X-Rembrane-Request-Id` and `X-Rembrane-Protocol-Version` in every
   operation response, including errors.
4. Return direct OpenAPI result or closed error bodies.
5. Derive tenant identity from authentication rather than request content.
6. Enforce protocol idempotency, optimistic versions, ordered sync, and
   response limits.

First, perform a content-free discovery and negotiation check:

```sh
rembrane memory-provider check
```

The check requires an `end_to_end_encrypted` provider by default. Operators
must explicitly acknowledge a weaker deployment model:

```sh
rembrane memory-provider check --privacy trusted-boundary
rembrane memory-provider check --privacy provider-plaintext
```

The command prints provider identity, version, privacy mode, capabilities,
required privacy mode, domains, and limits as JSON. It never prints the bearer
token or memory content. Because discovery is intentionally public, this check
validates token format but does not prove that the provider will authorize that
token; the black-box conformance test below verifies authenticated operations.

Before production use, run the black-box conformance client:

```sh
REMBRANE_MEMORY_PROVIDER_BASE_URL=https://memory.example.com \
REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN="$PRIMARY_TOKEN" \
REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN="$OTHER_TOKEN" \
REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN="$READONLY_TOKEN" \
./scripts/test-memory-provider-http.sh unique-test-namespace
```

For a dependency-light runner requiring only Node.js, use:

```sh
node scripts/run-memory-provider-conformance.mjs unique-test-namespace
```

It consumes the same three actor tokens and canonical profile/fixture
environment variables, rejects redirects and oversized responses, cleans up
created fixtures, and emits the same portable conformance result.

Use isolated test workspaces and short-lived tokens. The client creates and
deletes fixtures, verifies cross-workspace denial, and emits a credential-free
JSON result. The result carries the exact reviewed profile and lifecycle
fixture identifiers; compatibility verification rejects evidence attributed to
another test definition. It also records SHA-256 digests of both exact input
files so evidence remains unambiguous across reviewed pre-stable revisions.
