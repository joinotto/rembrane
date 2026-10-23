# ADR 0002: Canonical core and derived memory engines

- Status: Accepted
- Date: 2026-10-23

## Context

Mem0, Hindsight, Supermemory, Graphiti, Cognee, and other systems provide valuable extraction, retrieval, reflection, or graph capabilities. None should implicitly own Rembrane identity, workspace authorization, encryption, evidence, correction, deletion, or portability.

## Decision

Rembrane owns:

- Canonical users, workspaces, entities, activities, events, and memory versions.
- Provenance and confirmation state.
- Authorization and disclosure decisions.
- Encryption orchestration and key references.
- Correction, supersession, deletion, export, and synchronization semantics.

External memory, vector, graph, and model systems are replaceable derived providers. They receive only authorized projections and return candidate IDs, scores, relationships, summaries, or proposals. Every result is re-authorized against canonical records before disclosure.

The first semantic-provider benchmark will include a native baseline and Mem0 OSS. Graphiti is the initial temporal-graph candidate. Supermemory is an optional external integration and benchmark, not a required core component.

## Consequences

- Provider outages or migrations do not remove canonical memory.
- Rembrane must implement provider synchronization and deletion lineage.
- Approximate indexes may be rebuilt.
- Some provider-native features require explicit mapping or remain unsupported.
