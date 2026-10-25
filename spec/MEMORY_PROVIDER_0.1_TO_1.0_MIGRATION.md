# Memory Provider Protocol 0.1 to 1.0 migration

This document defines the migration contract for the future Memory Provider
Protocol `1.0` release candidate. It is review-locked before the release so a
candidate cannot silently omit operator or implementer migration guidance.
Protocol `0.1` remains the only published generation today; this document does
not announce `1.0` stability.

## Compatibility classification

The `1.0` generation is a major-version transition because `0.1` is a
pre-stable contract. A `1.0` provider must not claim wire compatibility with a
client requesting major generation `0`, and a `0.1` provider must reject a
client requesting major generation `1`. Implementations may offer both
generations concurrently only through separately versioned discovery,
operation paths, schemas, and conformance results.

## Provider implementers

Before advertising `1.0`, a provider must:

1. implement the exact reviewed `1.0` discovery and operation schemas;
2. preserve workspace and subject isolation, idempotency, optimistic
   concurrency, disclosure evidence, and strictly ordered sync semantics;
3. run the `1.0` core profile in a new disposable namespace;
4. publish a result pinned to the provider build, source revision, profile,
   fixtures, and ordered case list;
5. reject unsupported major generations before processing memory content; and
6. retain `0.1` only as an explicitly separate endpoint if its support window
   remains active.

Provider databases are implementation-owned. Canonical Rembrane memory remains
the source of truth, so a provider upgrade must rebuild or migrate only
derived indexes unless that provider separately documents durable canonical
storage.

## Client implementers

Clients must request one exact protocol generation and validate the response
generation and correlation ID on every operation. They must rediscover
capabilities, transports, privacy mode, domains, and limits after changing
generation. A client must not retry a rejected `0.1` request against `1.0`
without explicit operator or application upgrade intent.

## Operators

An operator migration must:

1. back up canonical encrypted memory and provider configuration;
2. deploy the candidate provider without replacing the working `0.1`
   endpoint;
3. verify authentication, tenant isolation, and the full candidate
   conformance result;
4. rebuild derived provider projections in a disposable or versioned
   namespace;
5. switch clients only after reviewing the compatibility classification and
   retained release evidence; and
6. keep rollback possible without accepting `1.0`-written state through a
   `0.1` parser.

No raw workspace key, provider bearer token, subject identifier, or memory
content belongs in migration evidence.

## Release-candidate completion

The final `1.0` release changes every canonical protocol-version declaration
and versioned HTTP path together, regenerates the compatibility lock through
review, updates this document with concrete field and operation differences,
and records the required external-provider, mixed-version, security-review,
and full-suite evidence. Until then, all examples describing `1.0` are test
fixtures rather than production evidence.
