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

- [Product Requirements and Architecture](docs/PRODUCT_REQUIREMENTS_AND_ARCHITECTURE.md)
- [Rust Architecture Research](docs/RUST_ARCHITECTURE_RESEARCH.md)
- [Bot and Platform Integration Architecture](docs/BOT_AND_PLATFORM_INTEGRATION_ARCHITECTURE.md)
- [Support and Compatibility Policy](docs/SUPPORT_POLICY.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Architecture Decision Records](docs/adr/README.md)
- [Roadmap](ROADMAP.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

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

## Contributing

Rembrane is being built in public. Start with [CONTRIBUTING.md](CONTRIBUTING.md), read the [support policy](docs/SUPPORT_POLICY.md), and discuss substantial protocol or security changes before implementing them.

## License

Licensed under the Apache License, Version 2.0.
