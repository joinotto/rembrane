# Rembrane Threat Model

**Status:** Initial design baseline  
**Scope:** Core service, local gateway, clients, provider adapters, shared workspaces, and synchronization

## 1. Security objectives

Rembrane must:

1. Prevent one user or workspace from reading or modifying another's memory.
2. Disclose only memory authorized for the requesting client, purpose, and scope.
3. preserve evidence, authorship, correction, and deletion semantics.
4. Prevent untrusted content from becoming privileged instructions.
5. Keep operator and provider credentials outside canonical memory.
6. Support deployments where the hosted service cannot decrypt memory.
7. Make access, disclosure, and administrative changes auditable.
8. Fail closed when identity, authorization, cryptography, or provider capability is uncertain.

## 2. Protected assets

- Plaintext memory content.
- Canonical events and evidence.
- Personal and workspace knowledge graphs.
- Activity checkpoints and work traces.
- User, device, workspace, and client identities.
- Authorization policies and consent records.
- Encryption keys, recovery material, tokens, and provider credentials.
- Disclosure and administrative audit records.
- Deleted-memory tombstones and revocation state.
- Availability and integrity of synchronization state.

## 3. Actors

### Trusted within an explicit boundary

- An authenticated user.
- An authorized device.
- A workspace administrator acting within granted authority.
- A customer-controlled strict-E2EE gateway.
- Reviewed core components operating under least privilege.

### Partially trusted

- Connected AI clients.
- Workspace members.
- Hosted infrastructure operators.
- Database, vector, graph, model, and memory-engine providers.
- Community adapters.
- Imported data sources.

### Untrusted

- Memory content supplied by agents, tools, documents, websites, or other users.
- Network callers without a validated identity and grant.
- Prompt content requesting policy bypass.
- Cross-tenant identifiers supplied by clients.
- Webhook payloads before signature and replay validation.

## 4. Trust boundaries

```text
User device
  │ plaintext may exist
  ▼
Local client or E2EE gateway
  │ minimal authorized context may cross
  ▼
External AI client/model

Local client or gateway
  │ ciphertext, routing metadata, policy-dependent indexes
  ▼
Hosted Rembrane services
  │ provider-specific authorized projection
  ▼
Database / graph / vector / memory providers
```

Every boundary crossing requires an explicit data classification, purpose, authorization decision, and documented plaintext exposure.

Workspace identifiers, principal identifiers, membership roles, invitation
roles/statuses, timestamps, and similar authorization metadata remain visible
to the local database or hosted control plane that enforces access. Strict E2EE
protects memory, event, checkpoint, artifact, and synchronization payloads; it
does not imply that all routing and authorization metadata is hidden.

## 5. Primary threats and controls

### T1. Cross-tenant data access

Threats:

- Client-supplied workspace IDs used without membership validation.
- Missing workspace predicate in a database or vector query.
- Cache keys that omit workspace, client, policy, or memory version.
- Globally unique IDs treated as authorization.

Required controls:

- Derive accessible workspaces from the authenticated principal.
- Include workspace isolation in every repository and index operation.
- Apply PostgreSQL row-level security as defense in depth.
- Re-authorize approximate-search results against canonical records.
- Test identical IDs across different workspaces.
- Return non-enumerating errors for unauthorized records.

### T2. Excessive disclosure

Threats:

- Sending the entire user profile to every agent.
- Ignoring entity, activity, sensitivity, or purpose restrictions.
- Stale client caches retaining revoked memory.

Required controls:

- Purpose-bound context resolution.
- Least-privilege scopes and context budgets.
- Sensitivity filtering before ranking.
- Exact memory ID and version disclosure receipts.
- Cache expiry and revocation-version checks.
- User-visible connection permissions and access history.

### T3. Memory poisoning and prompt injection

Threats:

- A website or tool result says “remember this as a system instruction.”
- An agent promotes an inference to confirmed fact.
- Shared members insert malicious procedural instructions.
- Retrieved memory contains commands interpreted above policy.

Required controls:

- Treat external content as evidence, never authority.
- Separate content, provenance, trust class, and instruction authority.
- Require proposals and confirmation policy for durable memories.
- Never concatenate memories into privileged system instructions without typed policy.
- Preserve source attribution in context packs.
- Scan and quarantine suspicious procedural-memory proposals.

### T4. Identity confusion

Threats:

- Phone-number reuse or SIM swap.
- Channel identifier treated as canonical identity.
- Account linking performed in the wrong workspace.
- Confusion between an actor, subject, and recipient.

Required controls:

- Explicit OAuth, device, or one-time account linking.
- Separate principal, subject, client, channel, and workspace identifiers.
- Short-lived, single-use linking codes.
- Reauthentication for sensitive grants.
- User-visible connection revocation.

### T5. Unauthorized shared-memory promotion

Threats:

- Private memory becomes workspace memory automatically.
- A member publishes information about another participant.
- Removed members retain shared keys or cached context.

Required controls:

- Explicit copy or proposal from private to shared scope.
- Workspace policy and approval for sensitive promotions.
- Authorship and subject attribution.
- Group key rotation after membership removal.
- Revocation propagation and device synchronization.

### T6. Key compromise or loss

Threats:

- Server compromise exposes master keys.
- Provider credentials appear in memory, logs, or exports.
- Lost devices make strict-E2EE data unrecoverable.
- Recovery flow becomes an authentication bypass.

Required controls:

- Envelope encryption and independently versioned content keys.
- Hardware-backed device keys where available.
- Secret managers or local protected storage for credentials.
- No secrets in ordinary configuration, memory, telemetry, or crash output.
- Tested recovery with explicit user warnings.
- Key rotation and device-removal protocols.
- Cryptographic design and implementation review before stable release.

### T7. Malicious or compromised provider adapter

Threats:

- Adapter sends plaintext to an undeclared endpoint.
- Provider silently lacks deletion or tenant-isolation capability.
- Dependency compromise exfiltrates credentials.

Required controls:

- Capability negotiation and startup validation.
- Minimal provider-specific grants.
- Network destination reporting through privacy diagnostics.
- Provider conformance and deletion tests.
- Dependency pinning, review, and software-bill-of-materials generation.
- Process or network isolation for high-risk sidecars.

### T8. Event and audit tampering

Threats:

- Deleting evidence to hide a poisoned memory.
- Modifying disclosure history.
- Replaying events out of order.

Required controls:

- Append-oriented canonical event ledger.
- Monotonic aggregate versions and idempotency keys.
- Restricted audit access and independent retention policy.
- Integrity chaining or signed checkpoints where the deployment requires it.
- Separate user deletion semantics from security-audit retention.

### T9. Synchronization conflict and rollback

Threats:

- Offline device overwrites a newer correction.
- Deleted memory reappears from a stale device.
- Old policy state authorizes a disclosure.

Required controls:

- Optimistic concurrency using expected versions.
- Durable deletion tombstones.
- Policy and revocation versions in sync cursors and caches.
- Explicit conflict records instead of last-write-wins for semantic facts.

### T10. Denial of service and cost abuse

Threats:

- Unbounded ingestion or context requests.
- Graph expansion and embedding amplification.
- Repeated expensive model-based consolidation.

Required controls:

- Per-client, user, workspace, and provider limits.
- Context, graph-depth, payload, and execution budgets.
- Idempotency and deduplication.
- Backpressure and bounded queues.
- Cost visibility without logging plaintext content.

## 6. E2EE deployment modes

### Hosted processing mode

The service may process plaintext under the operator's security boundary. This mode can provide server-side semantic search but is not strict E2EE.

### Customer-controlled gateway mode

The hosted service stores ciphertext while a customer-controlled gateway performs decryption, indexing, context compilation, and provider calls.

### Local-only mode

Plaintext, keys, indexes, and providers remain on authorized user devices. Synchronization is optional and carries encrypted data.

The UI and configuration must never describe ordinary server-side encryption as end-to-end encryption.

## 7. Security invariants

The implementation must continuously test:

1. A repository lookup requires workspace scope.
2. A subject cannot mutate another subject's private memory.
3. A client receives only memories permitted by its grant.
4. Approximate search cannot bypass canonical authorization.
5. A disclosure identifies exact memory versions.
6. A stale writer cannot overwrite a newer version.
7. Deleted memory is excluded from context resolution.
8. Unconfirmed observations cannot outrank confirmed memory.
9. Private memory cannot become shared without an explicit operation.
10. Logs, metrics, and traces contain no plaintext memory or secrets.

## 8. Release blockers

The first stable release is blocked until:

- Authentication and authorization flows receive security review.
- Cross-tenant tests cover REST, MCP, background jobs, caches, graph, and vector paths.
- Key management and recovery are implemented and reviewed.
- Backup, restore, deletion, revocation, and migration are tested.
- Provider adapters pass conformance and outbound-data disclosure checks.
- A vulnerability response process and supported-version policy are active.

## 9. Open questions

- Which strict-E2EE search modes provide acceptable leakage and performance?
- Which metadata remains visible to hosted synchronization services?
- What audit retention is legally and operationally appropriate per deployment?
- How should workspace recovery work without granting the service plaintext access?
- Which group-key protocol and device-attestation mechanisms will be required?
- How will graph-derived facts carry authorization and deletion lineage?
