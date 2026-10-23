# ADR 0001: Rust modular monolith

- Status: Accepted
- Date: 2026-10-23

## Context

Rembrane needs strong isolation, portable self-hosting, several API surfaces, background projection, and replaceable providers. Starting with separately deployed microservices would increase operational and consistency complexity before service boundaries are proven.

## Decision

Build the authoritative core as a Rust modular monolith with multiple binaries sharing domain and application crates.

Dependency direction is:

```text
domain ← application ← adapters and applications
```

The domain must not depend on HTTP frameworks, databases, clouds, models, graph engines, or semantic-memory providers.

Initial binaries will eventually include:

- `rembrane-server`
- `rembrane-worker`
- `rembrane-cli`
- `rembrane-local`

Modules may run as separate processes where deployment or security boundaries require it, but they retain one canonical application model.

## Consequences

- Cross-record consistency can use ordinary database transactions.
- Local and hosted deployments share core behavior.
- Provider replacement is enforced through ports.
- Independent service scaling is deferred until measurements justify extraction.
