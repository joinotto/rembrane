# ADR 0006: Keep record encryption behind an opaque boundary

## Status

Accepted

## Context

Canonical memories, events, and activity checkpoints require authenticated
encryption. Storage adapters need ciphertext metadata, but application and
provider code must not receive raw workspace keys or implement cryptographic
operations independently.

Ciphertext must also be bound to its tenant and logical record. Otherwise, a
valid encrypted payload could be copied into another workspace, record,
version, or payload type without immediate detection.

## Decision

`rembrane-crypto` owns the provider-independent record-encryption contract.
Callers pass plaintext and an `EncryptionContext`; implementations return an
opaque `EncryptedPayload` containing ciphertext, key reference, algorithm
identifier, and nonce.

The encryption context produces stable, length-delimited associated data from:

- workspace identifier;
- record identifier;
- record version;
- payload purpose.

Concrete algorithm, operating-system keychain, HSM, KMS, and customer key
providers live in adapter crates. The core contract never exposes raw key
bytes.

Algorithm selection remains open until the security review described in the
threat model. Implementations must fail closed for unknown algorithms, missing
keys, malformed envelopes, and authentication failures.

## Consequences

- Storage schemas can remain algorithm-agile.
- Cross-workspace and cross-record ciphertext substitution is detectable.
- Hosted, local, and customer-controlled key providers share one application
  boundary.
- Serialization and encryption adapters must be supplied before the SQLite
  store can persist domain records.
- This boundary does not by itself provide strict E2EE; deployment topology
  still determines where plaintext processing occurs.
