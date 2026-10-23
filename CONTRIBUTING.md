# Contributing to Rembrane

Thank you for helping build portable, user-owned memory infrastructure.

## Before contributing

1. Read the [support policy](docs/SUPPORT_POLICY.md).
2. Review the [product architecture](docs/PRODUCT_REQUIREMENTS_AND_ARCHITECTURE.md).
3. Search existing issues and discussions before proposing substantial work.
4. Open a design discussion before changing protocols, cryptography, authorization, identity, tenancy, or canonical schemas.

## Development principles

- Protect user privacy and tenant isolation before optimizing convenience.
- Keep the domain independent of databases, clouds, models, and memory engines.
- Prefer stable provider contracts over hard-coded vendor integrations.
- Treat generated memories as proposals until policy permits confirmation.
- Preserve provenance, correction, deletion, and disclosure records.
- Avoid undocumented platform bypasses in official integrations.

## Commit style

Use small, reviewable commits with an imperative conventional prefix:

```text
feat: add context resolution contract
fix: prevent cross-workspace lookup
docs: define provider capability negotiation
test: cover memory supersession
chore: configure rust linting
```

## Pull requests

Pull requests should include:

- The problem and intended behavior.
- Security and privacy impact.
- Compatibility or migration impact.
- Tests or an explanation of why tests are not applicable.
- Documentation updates for public behavior.

Changes affecting stored data or protocols require a migration and compatibility plan.

Run the architecture guard before submitting:

```text
./scripts/check-architecture.sh
./scripts/check-sensitive-files.sh
./scripts/test-sqlite-schema.sh
./scripts/test-sqlite-atomicity.sh
```

## Security-sensitive changes

Do not publicly disclose a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).

Cryptographic primitives must come from reviewed libraries. New cryptographic designs require an explicit design review and must not be merged solely on passing tests.

## Developer Certificate of Origin

Contributions use the Developer Certificate of Origin. Sign commits with:

```text
git commit -s
```

The sign-off certifies that you have the right to submit the contribution under this project's license.
