# ADR 0008: Key providers expose operations, not raw keys

## Status

Accepted for the pre-alpha provider protocol.

## Context

Rembrane must support OS keychains, HSMs, customer KMS systems, and local
software keys without coupling canonical storage to vendor SDKs. A generic
“fetch key bytes” API would move long-lived workspace keys into every caller
and defeat hardware-backed or non-exportable key guarantees.

## Decision

External key providers implement the versioned Key Provider Protocol and expose
authenticated `seal` and `open` operations. They never return raw workspace key
material. Every request carries the complete canonical encryption context:
workspace, record, version, and payload purpose.

The provider is part of the plaintext trusted boundary. It may run:

- over a Unix-domain socket;
- on authenticated loopback; or
- across a customer-controlled mutually authenticated channel.

Public unauthenticated endpoints and remote plaintext HTTP are forbidden.
Bearer authentication in the initial OpenAPI contract is a minimum transport
control, not a substitute for process isolation, TLS, or workload identity.

Responses use the same opaque envelope fields as `RecordCipher`: ciphertext,
key identifier, algorithm, and nonce. Historical-key lookup is strictly by the
envelope key identifier. Providers must fail closed for an unknown key,
unsupported algorithm, mismatched context, or failed authentication.

Clients negotiate and cache one validated manifest before use. Every operation
uses a bounded, deployment-unique request namespace plus a monotonic suffix;
deployments should generate the namespace with enough entropy to avoid replay
collisions across process restarts.

## Consequences

- Raw keys can remain non-exportable inside an HSM, KMS gateway, or keychain
  adapter.
- Canonical storage remains vendor-neutral.
- Plaintext crosses the provider boundary, so deployment placement and channel
  security are part of the E2EE claim.
- Provider conformance must test context substitution, unknown keys, size
  limits, authentication, and the absence of key material in responses or
  logs.
