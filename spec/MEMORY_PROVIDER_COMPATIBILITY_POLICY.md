# Memory Provider Protocol compatibility policy

This policy governs published Memory Provider Protocol versions. Protocol
versions are `MAJOR.MINOR` generations; they are independent from provider
implementation package versions.

## Negotiation

A client declares the minimum protocol version it implements. A provider is
compatible only when:

- its major generation exactly equals the client's required major; and
- its minor version is greater than or equal to the client's required minor.

After negotiation, requests and responses carry the exact client protocol
version. A response with another version or request correlation ID is rejected.
Capabilities, transports, privacy mode, domains, and operation limits are
negotiated separately and always fail closed.

## Compatible minor changes

A minor release may:

- add an optional field with a defined absence meaning;
- add an optional capability or operation that old clients never invoke;
- increase a numeric maximum without weakening an existing minimum;
- clarify text without changing observable behavior; or
- tighten a rejection that was already required by the normative contract.

A minor release must not require an old client to send new data or understand
new closed-enum values. Providers advertising a newer minor version must
continue serving requests from every supported earlier minor in that major
generation.

## Breaking changes

The following require a new major generation:

- removing or renaming a field, operation, capability, scope, or error code;
- adding a required field or changing a field's type, bounds, or meaning;
- adding a value to a closed enum without an existing unknown-value rule;
- changing authentication, tenant derivation, idempotency, ordering,
  optimistic concurrency, encryption, or disclosure semantics;
- weakening a validation or privacy guarantee; or
- changing an HTTP method, canonical path, correlation header, or status
  interpretation.

Because `0.1` already uses same-major minor negotiation, a breaking pre-`1.0`
wire change must not be published as `0.2`. It requires the `1.0` generation or
an explicit negotiation redesign reviewed as a breaking change.

## Deprecation and support

- Deprecation is documented in discovery, release notes, and migration
  guidance before removal.
- A stable operation remains available for at least two minor releases and
  180 days after deprecation, whichever is longer.
- A superseded stable major generation receives security fixes for at least
  12 months after the next major release.
- An actively exploited security flaw may require faster disablement. The
  release must document the threat, affected versions, compensating controls,
  and migration path.

## Release evidence

Every protocol release updates the compatibility lock through review, records
its compatibility classification in `CHANGELOG.md`, passes the canonical
conformance profile, and includes mixed-version tests for the oldest and newest
supported minors. A major release also publishes migration guidance and
cross-generation rejection tests.
