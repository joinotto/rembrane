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
export REMBRANE_GRAPHITI_BEARER_TOKEN="$(openssl rand -hex 32)"
export REMBRANE_GRAPHITI_NEO4J_PASSWORD="$(openssl rand -hex 32)"
export REMBRANE_GRAPHITI_OPENAI_API_KEY='replace-from-secret-manager'
```

Start Rembrane with the optional projection data plane:

```text
docker compose -f compose.yaml -f compose.graphiti.yaml up --build -d
```

The adapter accepts an endpoint and secret reference shaped as:

```text
REMBRANE_GRAPH_PROVIDER=graphiti
REMBRANE_GRAPHITI_BASE_URL=http://127.0.0.1:8793
REMBRANE_GRAPHITI_TOKEN_REF=env:REMBRANE_GRAPHITI_BEARER_TOKEN
```

The token reference is configuration metadata; its value remains in the local
environment or secret manager. Automatic worker construction from these
variables is tracked separately; until that wiring lands, applications compose
the `rembrane-graph-graphiti` and `rembrane-graph-graphiti-http` crates
explicitly.

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
