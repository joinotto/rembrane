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

The current slice exposes an injectable `Mem0Transport` and passes the shared
semantic-provider conformance harness. The authenticated HTTP transport and a
real disposable Mem0 conformance run remain required before the adapter can
appear as compatible in the provider registry.

Deployments using hosted or self-hosted Mem0 process plaintext within that
provider boundary. They must explicitly permit plaintext processing, keep the
workspace lookup secret and Mem0 credential in their own secret manager, and
use an authenticated endpoint. Strict-E2EE deployments must not send
plaintext projections to a remote Mem0 service.
