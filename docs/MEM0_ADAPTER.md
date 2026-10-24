# Mem0 OSS semantic adapter

Rembrane treats Mem0 as replaceable derived semantic state, never as the owner
of canonical identity, authorization, evidence, correction, or deletion.

The Rust mapping adapter accepts only already-authorized canonical
projections. It derives a provider `user_id` by HMAC-signing the workspace ID
with a deployment-owned lookup secret, so raw workspace identifiers are not
sent to Mem0. Records retain canonical memory ID and version metadata.

Indexing replaces every older provider record for the same canonical memory.
Search returns bounded canonical candidates and collapses duplicate provider
records to the newest version. Deletion removes only matching versions up to
the requested bound.

`HttpMem0Transport` connects to an HTTPS origin, or exact loopback HTTP for
local development, using the Mem0 OSS `X-API-Key` header. It disables
redirects and environment proxies, applies strict timeouts, bounds JSON
responses, stores the credential in zeroizing memory, uses `infer=false` for
exact projections, and percent-encodes provider record IDs before deletion.

The mapping layer passes the shared semantic-provider conformance harness. A
real disposable Mem0 conformance run remains required before the adapter can
appear as compatible in the provider registry.

Deployments using hosted or self-hosted Mem0 process plaintext within that
provider boundary. They must explicitly permit plaintext processing, keep the
workspace lookup secret and Mem0 credential in their own secret manager, and
use an authenticated endpoint. Strict-E2EE deployments must not send
plaintext projections to a remote Mem0 service.

Applications can construct the provider without fixed configuration names:

```rust
let provider = Mem0SemanticProvider::from_http(
    mem0_origin,
    resolved_api_key,
    resolved_workspace_lookup_secret,
)?;
```

Resolve both secrets from the operator's keychain, vault, container secret, or
cloud secret manager. Never reuse the API key as the workspace lookup secret.

The CLI can execute the destructive shared conformance suite against an
operator-owned disposable Mem0 instance. It requires `MEM0_BASE_URL`,
`MEM0_API_KEY`, `MEM0_WORKSPACE_LOOKUP_SECRET`, a unique namespace, and the
explicit `--allow-provider-plaintext` acknowledgement. See `docs/TESTING.md`.
