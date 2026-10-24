# Supermemory v5 adapter decision

## Status

Planned community semantic provider. Do not advertise compatibility until a
disposable-namespace conformance run passes.

## Why v5

The adapter targets Supermemory's stable v5 namespace API rather than the
legacy v3/v4 container-tag API:

- ingest: `POST /ns/{namespace}/document`;
- search: `POST /ns/{namespace}/search`;
- list: `POST /ns/{namespace}/list/memories`;
- exact forgetting: `DELETE /ns/{namespace}/memories`;
- source deletion: `DELETE /ns/{namespace}/document`.

References:

- <https://supermemory.ai/docs/v5/api-reference/overview>
- <https://supermemory.ai/docs/v5/api-reference/search>
- <https://supermemory.ai/docs/v5/api-reference/content-management>
- <https://supermemory.ai/docs/v5/api-reference/ingest>

## Canonical mapping

Rembrane remains authoritative. Supermemory receives only an authorized
plaintext projection inside an explicitly permitted provider boundary.

| Rembrane value | Supermemory value |
| --- | --- |
| workspace ID | HMAC-derived namespace |
| memory ID | keyed deterministic caller-defined document ID |
| memory version | numeric metadata |
| memory content | document content |
| scope and kind | bounded metadata |

The namespace lookup secret is independent from the API credential. The
derived namespace must match Supermemory's documented 100-character safe
pattern and must not reveal the canonical workspace ID. Namespace and document
pseudonyms use distinct HMAC domain labels.

The adapter validates generated namespaces against the documented ASCII
letters, digits, underscore, colon, and hyphen alphabet before transport use.
It applies the same path-safe alphabet to deterministic document IDs, so
canonical memory identifiers never enter provider URLs or request identity
fields.

## Required behavior

The provider adapter must:

1. use bearer authentication with zeroizing credential custody;
2. require HTTPS except literal loopback IPs for a local deployment;
3. disable redirects and environment proxies;
4. apply strict connection, request, and response-size limits;
5. send deterministic document identity and exact canonical metadata;
6. poll bounded processing status before reporting an index operation ready;
7. collapse search results to the newest canonical version;
8. perform exact-ID deletion rather than semantic deletion;
9. verify partial-delete responses and fail if the requested identity was not
   removed;
10. never delegate authorization, tenant identity, or canonical truth to
    Supermemory.

## Replacement semantics

Supermemory ingestion may be asynchronous. A successful HTTP acceptance is not
proof that the new version is searchable or that the old version disappeared.
The adapter must model indexing as retryable derived work:

1. upsert the deterministic document ID;
2. poll a bounded status endpoint until processing reaches a terminal state;
3. verify the new canonical version through a scoped list or search;
4. only then allow the projection job to complete.

Timeout, rate limiting, partial deletion, or non-terminal processing leave the
canonical outbox job retryable. Canonical memory is never rolled back.

The Rust `SupermemoryTransport` contract therefore requires a separate
`await_ready` operation after ingestion. A transport cannot represent HTTP
acceptance as completed indexing.

Deletion similarly returns explicit confirmation for the requested provider
identity. A partial-success response that omits or fails that identity is a
retryable failure.

## Privacy

Hosted Supermemory processes plaintext and is incompatible with strict E2EE.
Self-hosting changes placement, not the fact that the semantic engine sees
plaintext. Operators must explicitly permit provider plaintext and keep the
API key and namespace HMAC secret in their own secret manager.

## Promotion evidence

Before registry promotion:

- pass the shared semantic-provider conformance suite;
- capture the pinned Supermemory version and API version;
- prove cross-workspace denial;
- prove exact replacement and deletion after processing convergence;
- prove credentials and canonical workspace IDs do not appear in logs;
- record reviewable disposable-instance evidence in the provider registry.

