# Memory Provider Protocol stability

Memory Provider Protocol `0.1` is review-locked but not stable. The
compatibility lock prevents accidental wire changes; it does not by itself
provide the interoperability history required for a `1.0` stability promise.

## Evidence already present

- Canonical JSON Schema and OpenAPI operation binding.
- A transport-neutral Rust SDK and authenticated HTTP client.
- A machine-readable core conformance profile and lifecycle fixtures.
- A black-box conformance runner with independent loopback coverage.
- A tamper-tested compatibility lock over the reviewed protocol artifacts.
- Configured provider composition with explicit privacy policy and
  secret-reference handling.

## Gates for `1.0`

All of the following are required before changing the public protocol version
to `1.0` and marking the roadmap milestone complete:

1. Record passing core-conformance results for at least two independently
   implemented providers, including one implementation outside this
   repository. Evidence must pin the provider build, disposable namespace,
   profile digest, fixture digest, and ordered case results.
2. Complete an independent security review of authentication, tenant
   isolation, idempotency, optimistic concurrency, disclosure evidence, sync
   ordering, and secret handling. Track every finding to resolution or an
   explicitly documented accepted risk.
3. Publish a compatibility policy defining additive versus breaking changes,
   deprecation periods, supported protocol generations, and client/provider
   negotiation behavior.
4. Exercise mixed-version client/provider compatibility, including supported
   minor-version negotiation and fail-closed major-version rejection.
5. Freeze the complete `1.0` artifact inventory, regenerate its compatibility
   lock through the reviewed release process, and publish migration notes from
   `0.1`.
6. Run the full SDK, HTTP adapter, configured-provider, black-box conformance,
   compatibility-tamper, and static security suites against the release
   candidate.

Until these gates are met, integrations should pin protocol `0.1`, pin exact
conformance evidence, and treat upgrades as reviewed deployment changes.
