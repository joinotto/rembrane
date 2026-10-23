# ADR 0007: Prototype record AEAD with RustCrypto

## Status

Accepted for experimental use

## Context

The encrypted SQLite adapter requires a real authenticated-encryption
implementation before persistent canonical memory can be exercised end to end.
Rembrane must reuse maintained cryptographic libraries and must not implement
an encryption algorithm.

The record format requires:

- authenticated encryption;
- a 256-bit content key;
- a unique random nonce per encryption;
- associated data binding tenant, record, version, and purpose;
- portable native support without requiring a system-installed library.

Shared-workspace key agreement, device key storage, recovery, and rotation are
separate concerns.

## Decision

Add an experimental adapter using the RustCrypto `chacha20poly1305` crate in
XChaCha20-Poly1305 mode. Nonces come from the operating system through
`getrandom`, and the in-process key container uses `zeroize`.

The adapter accepts a key and opaque key identifier from a future key-provider
boundary. It never generates, persists, wraps, rotates, or recovers workspace
keys.

The adapter remains experimental until:

- known-answer and corruption tests pass on supported platforms;
- key-provider integrations are complete;
- nonce and backup/restore behavior is reviewed;
- dependency provenance and advisories are continuously checked;
- an independent cryptographic implementation review is complete.

OpenMLS remains the planned group-key protocol for shared workspaces. This
record AEAD does not replace MLS.

## Consequences

- Local encrypted persistence can be integrated without custom cryptography.
- Record ciphertext stays bound to its canonical encryption context.
- Operators cannot yet safely supply keys through CLI arguments or plain
  configuration files.
- A future reviewed adapter may replace this implementation without changing
  canonical storage or application ports.
