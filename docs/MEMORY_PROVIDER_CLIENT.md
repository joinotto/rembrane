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
| `REMBRANE_MEMORY_PROVIDER_TOKEN` | Yes | OAuth access token or provider-issued bearer credential. |
| `REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX` | No | Diagnostic prefix containing 8–64 URL-safe characters. |

Do not commit tokens to `.env` files, Compose manifests, shell profiles, or
application configuration. Inject them from an OS keychain, container secret,
Kubernetes Secret, systemd credential, customer secret manager, or equivalent
deployment-owned facility. The adapter moves the loaded token into zeroizing
transport storage and never sends it to the public discovery endpoint.

The base URL must be an origin without embedded credentials, paths, query
parameters, or fragments. Remote plaintext HTTP is rejected. Loopback HTTP is
accepted only for `127.0.0.1`, `::1`, or `localhost`.

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

The command prints provider identity, version, privacy mode, capabilities,
domains, and limits as JSON. It never prints the bearer token or memory
content. Because discovery is intentionally public, this check validates token
format but does not prove that the provider will authorize that token; the
black-box conformance test below verifies authenticated operations.

Before production use, run the black-box conformance client:

```sh
REMBRANE_MEMORY_PROVIDER_BASE_URL=https://memory.example.com \
REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN="$PRIMARY_TOKEN" \
REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN="$OTHER_TOKEN" \
REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN="$READONLY_TOKEN" \
./scripts/test-memory-provider-http.sh unique-test-namespace
```

Use isolated test workspaces and short-lived tokens. The client creates and
deletes fixtures, verifies cross-workspace denial, and emits a credential-free
JSON result.
