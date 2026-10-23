## Problem

Describe the user or developer problem.

## Change

Describe the behavior and implementation.

## Security and privacy

- What trust boundary or user data is affected?
- Can this change expose plaintext, credentials, identifiers, or metadata?
- How are workspace and subject isolation enforced?
- Does it affect revocation, correction, deletion, or recovery?

## Compatibility

- Protocol/schema impact:
- Migration impact:
- Provider/integration impact:

## Verification

- [ ] Tests cover the changed behavior.
- [ ] Cross-workspace and unauthorized paths were considered.
- [ ] Public behavior is documented.
- [ ] No secrets or plaintext memory enter logs, fixtures, or telemetry.
- [ ] Breaking changes include a migration or versioning plan.
