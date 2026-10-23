# Rembrane Protocol Specifications

This directory contains implementation-independent contracts for connecting AI clients, applications, bots, and provider adapters to Rembrane.

## Stability

All specifications are pre-alpha. Breaking changes are allowed until a version is explicitly marked stable.

## Discovery

A compatible deployment serves:

```text
GET /.well-known/ai-memory
```

The response must validate against `discovery.schema.json`. Discovery describes protocol endpoints and capabilities; it does not grant access. Clients still require an authorized connection and scoped credentials.

## REST API

`openapi.yaml` defines the versioned HTTP surface. The initial contract is deliberately narrow and grows only after the corresponding application use case and security invariants exist.

## MCP

`mcp.md` maps application use cases to tools, resources, prompts, connection identity, permissions, and safety annotations. MCP parameters deliberately exclude canonical workspace and subject identity.

## Local stdio connection manifest

`stdio-connection-manifest.schema.json` defines the secret-free local process
manifest emitted by `rembrane mcp-config --client generic`. Launchers resolve
the listed environment variables inside the operator-controlled environment;
the manifest never contains their values.

## Design rules

- Canonical identifiers are opaque strings.
- Capabilities are explicit; clients must not assume unsupported behavior.
- A missing security capability must fail closed.
- Extensions use namespaced keys.
- Protocol versions and schema versions are independent.
- Provider-specific fields must not enter canonical contracts.
