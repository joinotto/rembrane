# Governance

Rembrane currently uses a maintainer-led governance model.

## Roles

- Contributors submit issues, discussions, documentation, code, tests, and reviews.
- Maintainers triage work, review changes, manage releases, and enforce project policies.
- Security maintainers coordinate vulnerability response and security releases.

Roles are earned through sustained, constructive contribution and may be changed through a documented maintainer decision.

## Decision making

Routine changes are decided through pull-request review. Significant changes require a public design proposal and reasonable time for community feedback.

Significant changes include:

- Canonical schema or protocol changes.
- Cryptography, key management, identity, and authorization.
- Backward-incompatible SDK or provider changes.
- New official integration classes.
- Licensing or governance changes.

Maintainers seek consensus. When consensus is not practical, the maintainers document the decision, major alternatives, and rationale.

Security embargoes and private vulnerability response are exceptions to public decision making.

## Independence

The canonical protocol and core must remain usable without a Mesh AI Labs hosted service. Hosted products may add operational services, but open formats, provider contracts, export, and self-hosting must remain first-class.
