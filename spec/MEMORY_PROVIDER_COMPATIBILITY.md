# Memory Provider Protocol compatibility

The protocol remains pre-stable while its public version is `0.1`. Its
interoperability surface is nevertheless review-locked in
`memory-provider-compatibility-lock.json`.

The lock covers the canonical JSON schema, OpenAPI binding, conformance
schemas, core profile, and lifecycle fixtures. CI rejects an unreviewed change
to any locked artifact. A deliberate protocol change must:

1. classify the change as compatible or breaking;
2. update implementations, fixtures, and conformance expectations together;
3. update the protocol version when compatibility requires it;
4. regenerate the affected SHA-256 entries; and
5. explain the compatibility impact in `CHANGELOG.md`.

The lock is evidence of a reviewed wire-surface change, not permission to
silently rewrite history. Published protocol artifacts for a released version
remain immutable.
