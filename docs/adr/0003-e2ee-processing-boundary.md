# ADR 0003: Strict E2EE requires controlled plaintext processing

- Status: Accepted
- Date: 2026-10-23

## Context

Encryption at rest and TLS do not prevent a hosted service from reading plaintext during search, extraction, graph construction, or context compilation. Calling such a deployment end-to-end encrypted would mislead users.

## Decision

Rembrane distinguishes three processing modes:

1. Hosted processing: the hosted service may process plaintext.
2. Customer-controlled gateway: hosted services store ciphertext; the customer's gateway decrypts and processes memory.
3. Local-only: plaintext processing, indexes, and keys stay on authorized devices.

Only the second and third modes may be described as strict E2EE when their full data path satisfies that property.

Discovery, setup, diagnostics, and connection screens must disclose:

- Where plaintext processing occurs.
- Which providers receive plaintext.
- Which metadata is visible to hosted services.
- What recovery guarantees and loss risks apply.

## Consequences

- Strict-E2EE semantic search may require local encrypted indexes or controlled gateways.
- Managed hosted mode can offer simpler operation but has a different trust model.
- Provider credentials in self-hosted modes remain in the operator's environment.
