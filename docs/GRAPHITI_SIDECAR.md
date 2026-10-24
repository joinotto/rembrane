# Graphiti sidecar

Rembrane treats Graphiti as a replaceable derived projection, never as the
canonical memory store or authorization system. The Rust core authorizes an
operation, derives the workspace namespace, and sends only the graph projection
needed by the sidecar.

## Trust boundary

The sidecar processes decrypted node labels, aliases, and relationship facts.
For strict-E2EE deployments it must therefore run locally or inside the
customer-controlled trusted data plane. Do not point a strict-E2EE workspace at
an untrusted hosted sidecar.

Clients never receive Neo4j, Graphiti, or model credentials. These values are
read only by the sidecar:

- `REMBRANE_GRAPHITI_BEARER_TOKEN`
- `REMBRANE_GRAPHITI_NEO4J_PASSWORD`
- `REMBRANE_GRAPHITI_OPENAI_API_KEY`

The Compose overlay binds the authenticated sidecar to loopback and does not
publish Neo4j.

## Local deployment

Set secrets through the shell, a local uncommitted `.env`, Docker secrets, or
the operator's secret manager:

```text
install -m 600 /dev/null .rembrane-graphiti-token
install -m 600 /dev/null .rembrane-neo4j-auth
install -m 600 /dev/null .rembrane-openai-key
openssl rand -hex 32 > .rembrane-graphiti-token
printf 'neo4j/%s\n' "$(openssl rand -hex 32)" > .rembrane-neo4j-auth
printf '%s\n' 'replace-from-secret-manager' > .rembrane-openai-key
export REMBRANE_GRAPHITI_BEARER_TOKEN_FILE="$PWD/.rembrane-graphiti-token"
export REMBRANE_GRAPHITI_NEO4J_AUTH_FILE="$PWD/.rembrane-neo4j-auth"
export REMBRANE_GRAPHITI_OPENAI_API_KEY_FILE="$PWD/.rembrane-openai-key"
```

Start Rembrane with the optional projection data plane:

```text
docker compose -f compose.yaml -f compose.graphiti.yaml up --build -d
```

The worker accepts an endpoint and locally resolved secret shaped as:

```text
REMBRANE_GRAPH_PROVIDER=graphiti
REMBRANE_GRAPHITI_BASE_URL=http://127.0.0.1:8793
REMBRANE_GRAPHITI_BEARER_TOKEN='resolve-from-local-secret-store'
REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT=true
```

For a standalone or custom worker deployment,
`REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE` may select `env:VARIABLE` or a
protected `file:path` instead of the default bearer-token variable. The
resolved value remains zeroizing through HTTP transport construction. The
sidecar accepts the same locator grammar and rejects raw inline locators,
symbolic links, non-regular files, files with group/other permission bits,
empty values, and oversized values. The stock Compose overlay mounts the file
selected by `REMBRANE_GRAPHITI_BEARER_TOKEN_FILE` read-only into both
processes, so the matching credential is never interpolated into the Compose
service environment. Each image stages its mounted secrets into a bounded
private tmpfs, enforces runtime-user ownership and mode `0400`, and only then
drops root privileges; strict resolution therefore does not depend on
Compose preserving file-secret mode metadata.

The Graphiti store also accepts `NEO4J_AUTH_REFERENCE`,
`NEO4J_PASSWORD_REFERENCE`, and `OPENAI_API_KEY_REFERENCE`. A Neo4j auth
reference contains the official `username/password` form and must name the
same user as `NEO4J_USER`. The model key is inserted into the process
environment only while Graphiti constructs its provider client, then the
previous value is restored or removed. The stock overlay mounts protected
Neo4j-auth and model-key files instead of interpolating either credential into
container environment metadata.

The Compose overlay constructs the worker automatically and connects it to the
sidecar over the private container network.

## Security properties

- Fixed versioned routes; arbitrary Graphiti operations are not exposed.
- Bearer authentication on discovery and every graph operation.
- Constant-time token comparison and header-safe credential validation.
- One workspace-derived namespace per request.
- Deterministic physical UUIDs include the namespace, preventing identical
  canonical IDs in different workspaces from colliding.
- Edge endpoints must already exist in the same namespace.
- Same-version retries are accepted only when their payload digest matches.
- Stale writes and conflicting same-version payloads fail closed.
- Deletes are idempotent and bounded by canonical version.
- Request bodies and graph candidates are bounded.

Canonical records, audit events, deletion state, and projection jobs remain in
Rembrane's encrypted store. The sidecar can be rebuilt from the canonical
outbox after loss or replacement.

## Verification

Run the dependency-free sidecar contract and codec suite:

```text
./scripts/test-graphiti-sidecar.sh
```

The full repository gate also runs this suite:

```text
./scripts/check-local-alpha.sh
```

Production integration additionally requires reachable Graphiti, Neo4j, and
model-provider services. Use disposable workspaces and credentials for
integration tests.

CI also starts an explicitly gated in-memory sidecar and runs the Rust graph
provider conformance suite through the real authenticated HTTP adapter:

```text
python -m pip install -e 'sidecars/rembrane-graphiti[dev]'
./scripts/test-graphiti-http-e2e.sh
```

The in-memory server refuses startup unless
`REMBRANE_GRAPHITI_ENABLE_IN_MEMORY_TEST_SERVER=1`; production startup always
constructs the Graphiti/Neo4j store.
