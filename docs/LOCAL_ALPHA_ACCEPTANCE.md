# Local Alpha Acceptance Contract

This contract defines “ready for test” for the current Rembrane local alpha.
It does not claim production readiness or completion of later hosted, shared
workspace, mobile-channel, or ecosystem phases.

## Included functionality

- Personal, development/project, travel, and activity-scoped memory.
- Encrypted SQLite canonical storage and encrypted activity checkpoints.
- Confirmed preference creation, correction, deletion, and scoped recall.
- Proposed work-trace capture.
- Layered global, domain, entity, and activity context.
- Disclosure receipts for memory context and checkpoint resume.
- Local stdio MCP and authenticated loopback REST.
- Secret-safe Codex and Claude Code MCP configuration generation.
- Consistent, versioned encrypted backup and verified restore.
- Git state fingerprints for stale coding handoffs.
- Docker Compose packaging for the local REST deployment.

## Required acceptance checks

The full acceptance command is:

```text
./scripts/check-local-alpha.sh
```

It must pass:

1. architecture and sensitive-file guards;
2. protocol, OpenAPI, discovery, Postman, and MCP conformance;
3. SQLite schema v1-to-v2 migration and transaction atomicity;
4. Rust formatting, Clippy with warnings denied, and all unit tests;
5. complete encrypted CLI lifecycle and recovery drill;
6. MCP checkpoint, work-trace, scope-denial, and disclosure checks; and
7. REST authentication, disclosure, and tenant-isolation checks.

The repository includes executable coverage for backup, restore, v1-to-v2
migration, membership revocation, memory deletion, wrong-key denial, encrypted
payload tampering, and every read path implemented by the local SQLite,
in-memory, MCP, and REST adapters.

For an offline machine without Rust, run:

```text
./scripts/check-local-alpha.sh --static
```

Static success proves repository, protocol, shell, Compose, and raw SQLite
contracts only. It is not a substitute for the full executable command.

## Explicitly outside this alpha

- Production OS-keychain, HSM, or customer-KMS integration.
- Remote Streamable HTTP MCP and OAuth.
- Hosted PostgreSQL and row-level security.
- Shared-workspace invitations, group-key rotation, and forward secrecy.
- Native WhatsApp, iMessage, or unrelated closed-bot interception.
- Stable SDK and provider-protocol compatibility guarantees.
- Independent security audit.

These exclusions are roadmap phases, not hidden acceptance failures.
