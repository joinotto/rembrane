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

`remote-mcp.md` defines the authenticated Streamable HTTP boundary.
`oauth-protected-resource.schema.json` describes the RFC 9728 metadata used by
clients to discover the authorization server and narrowly scoped Rembrane
permissions. OAuth is an outer authorization ceiling; canonical Rembrane
authorization remains mandatory for every operation.

## Local stdio connection manifest

`stdio-connection-manifest.schema.json` defines the secret-free local process
manifest emitted by `rembrane mcp-config --client generic`. Launchers resolve
the listed environment variables inside the operator-controlled environment;
the manifest never contains their values.

## Provider adapter manifest

`provider-manifest.schema.json` defines capability negotiation between the
canonical Rembrane core and replaceable semantic providers such as native,
Mem0, or Graphiti adapters. Providers declare their protocol version, explicit
capabilities, plaintext-processing behavior, and hard request limits. Missing
security capabilities, incompatible protocol versions, and zero limits fail
closed before projection work begins. Rust manifests enforce the same provider
identifier, version, capability uniqueness, and non-zero limit constraints as
the JSON Schema.

`provider-openapi.yaml` defines the external HTTP sidecar transport for those
same semantics. It covers manifest negotiation, idempotent projection upserts,
version-bounded deletion, and workspace-bound candidate search. Provider
responses remain untrusted; the canonical core reauthorizes every candidate
before disclosure. `scripts/test-provider-http.sh` exercises this contract
against a disposable external-provider namespace.

Rust adapters can run `verify_semantic_provider` from
`rembrane-provider-sdk` against a disposable provider instance or tenant. The
shared harness verifies manifest compatibility, version fidelity, workspace
isolation, declared result limits, replacement, version-bounded deletion, and
deletion propagation using a temporary fixture namespace.

`provider-registry.schema.json` defines the public compatibility registry, and
`provider-registry.json` is the repository-maintained registry instance.
Registry entries are evidence records, not endorsements: they pin the tested
adapter revision, protocol versions, deployment and plaintext boundaries, and
dated conformance result. A passing entry is not a security certification.

Run `scripts/verify-provider-registry.sh` before publishing registry changes.
It rejects duplicate provider identities, invalid or future-dated evidence,
compatible providers without passing conformance, and native entries whose
pinned Git revision is absent locally.

Registry releases use detached Ed25519 signatures over the exact published
JSON bytes. Set `REMBRANE_REGISTRY_SIGNING_KEY` to a PEM private-key path and
run `scripts/sign-provider-registry.sh`; no private key belongs in this
repository. Consumers verify the JSON and `.sig` artifact with
`scripts/verify-provider-registry-signature.sh` and the release public key.
They must pin or obtain that public key through an independently trusted
channel; a public key downloaded beside its signature is not by itself a trust
anchor.

Published GitHub releases invoke `provider-registry-release.yml`. Configure
the repository secret `REMBRANE_REGISTRY_SIGNING_KEY_PEM` with the complete
Ed25519 private-key PEM. The workflow writes it to a mode-restricted temporary
file, validates and signs the registry, verifies the detached signature, then
deletes the key and uploads JSON, checksum, signature, and public key.

## Memory Provider conformance

`memory-provider-conformance.schema.json` and
`conformance/memory-provider-core.json` define the portable behavioral profile.
`memory-provider-fixtures.schema.json` and
`conformance/memory-provider-core-fixtures.json` define its language-neutral,
secret-free lifecycle inputs and actor scope expectations. Implementations may
consume the same fixtures from any language; credentials and authenticated
workspace identities are supplied by the test environment and never by the
fixture file.

`memory-provider-conformance-result.schema.json` defines the portable evidence
record emitted after a complete passing run. It pins the provider ID and
version, profile, fixture corpus, disposable namespace, and one result for
every profile case.

## Design rules

- Canonical identifiers are opaque strings.
- Capabilities are explicit; clients must not assume unsupported behavior.
- A missing security capability must fail closed.
- Extensions use namespaced keys.
- Protocol versions and schema versions are independent.
- Provider-specific fields must not enter canonical contracts.
