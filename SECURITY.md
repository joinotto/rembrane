# Security Policy

## Project status

Rembrane is pre-alpha and must not be used for production secrets or sensitive personal data.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities involving:

- Cross-user or cross-workspace data access.
- Authentication or authorization bypass.
- Encryption, key management, or recovery.
- Memory poisoning or untrusted-context escalation.
- Credential, token, or plaintext-memory exposure.
- Deletion, revocation, or audit-log failure.

Use GitHub private vulnerability reporting for `mesh-ai-labs/rembrane`. If private reporting is unavailable, contact the maintainers privately before publishing details.

Include affected versions or commits, reproduction steps, impact, and any suggested mitigation. Do not include real user memory or credentials.

## Supported versions

No released version is currently supported. This section will be updated with the first tagged release.

## Security architecture

The intended security model includes:

- Explicit tenant and workspace isolation.
- Least-privilege client grants.
- Encrypted transport and encrypted storage.
- Strict-E2EE modes using authorized devices or customer-controlled gateways.
- Provenance and disclosure receipts.
- Revocation and deletion propagation.
- No plaintext memory or credentials in logs and telemetry.

The local SQLite vertical slice currently verifies encrypted canonical records,
tenant-scoped reads, exact disclosure receipts, scope-bound grants, optimistic
correction/deletion, and encrypted backup/restore through executable tests.

They remain pre-alpha implementation claims, not independently audited
production guarantees. Production KMS/keychain providers, remote OAuth,
shared-workspace key rotation, rollback-resistant synchronization, and
independent cryptographic review are still required.

See `docs/THREAT_MODEL.md` and `docs/RECOVERY_MODEL.md`.
