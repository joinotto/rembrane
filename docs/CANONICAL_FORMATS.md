# Canonical encrypted payload formats

Rembrane encrypts versioned canonical payloads rather than Rust memory layouts
or provider-specific objects. This keeps persisted data portable across local,
self-hosted, and managed deployments.

## Compatibility rules

- Every payload carries a stable format name and integer format version.
- Decoders reject unknown formats, unknown versions, malformed records, and
  unknown fields.
- Existing versions are immutable after release.
- A breaking representation change creates a new version and migration.
- Golden fixtures are committed and tested byte-for-byte.
- Encryption associated data separately binds the payload to its workspace,
  record identifier, record version, and purpose.

## Memory format version 1

Format identifier: `rembrane.memory`

The JSON envelope contains:

- `format`: canonical format identifier;
- `version`: envelope format version;
- `record`: the complete canonical memory snapshot.

The record includes canonical identifiers, subject, scope, memory kind,
lifecycle status, content, record version, and ordered evidence references.
The JSON bytes are encrypted before they enter canonical persistent storage.

See
`crates/rembrane-codec/fixtures/memory-v1-confirmed-preference.json` for the
normative version-one fixture.

Checkpoint and event formats will follow the same envelope rules before their
persistent adapters are implemented.
