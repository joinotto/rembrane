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
3. Apply `MEMORY_PROVIDER_COMPATIBILITY_POLICY.md` to the release candidate
   and publish the required mixed-version evidence.
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

Mixed-version release evidence uses
`memory-provider-mixed-version-evidence.schema.json` and must pass
`verify-memory-provider-mixed-version-evidence.mjs`. The verifier binds the
current conformance profile and lifecycle fixtures, requires distinct
disposable namespaces, pins every client and provider build to a source
revision, proves both supported-minor directions, and requires rejection of an
unsupported major generation. The checked-in example is illustrative test
data, not release evidence.

A complete candidate evidence directory is accepted only by
`verify-memory-provider-release-evidence.mjs`. It contains exactly a manifest,
the mixed-version artifact, and two passing provider results. The manifest
hash-binds every artifact and requires distinct maintainers, provider IDs, and
disposable namespaces, pinned implementation revisions, ordered core cases,
and at least one externally maintained provider. Passing the verifier proves
artifact completeness; it does not substitute for actually obtaining the
external run or independent security review.
