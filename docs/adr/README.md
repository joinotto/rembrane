# Architecture Decision Records

Architecture Decision Records capture decisions that materially constrain Rembrane's implementation.

Statuses:

- Proposed
- Accepted
- Superseded
- Rejected

Changing an accepted decision requires a new ADR that links to and supersedes the previous record.

## Decisions

- [0001: Build a Rust modular monolith](0001-rust-modular-monolith.md)
- [0002: Keep a canonical core and derived engines](0002-canonical-core-and-derived-engines.md)
- [0003: Require controlled plaintext processing for strict E2EE](0003-e2ee-processing-boundary.md)
- [0004: Publish honest integration tiers](0004-honest-integration-tiers.md)
- [0005: Make canonical mutations atomic](0005-atomic-canonical-mutations.md)
- [0006: Keep record encryption behind an opaque boundary](0006-opaque-record-encryption-boundary.md)
- [0007: Prototype record AEAD with RustCrypto](0007-experimental-rustcrypto-record-aead.md)
- [0008: Key providers expose operations, not raw keys](0008-key-provider-operation-protocol.md)
