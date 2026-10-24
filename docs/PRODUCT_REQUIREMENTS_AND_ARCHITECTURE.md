# Rembrane

## Product Requirements, Use Cases, Technology Evaluation, and Recommended Architecture

**Status:** Draft for review  
**Research snapshot:** 23 October 2026  
**Initial domains:** Personal, Development by Project, Travel  
**Deployment goal:** Multi-user SaaS, private personal memory, and shared organizational workspaces  
**Rust architecture:** See `RUST_ARCHITECTURE_RESEARCH.md`

---

## 1. Executive summary

The product is a user-owned continuity and memory infrastructure for AI tools. A person or organization records information once, and every subsequently authorized AI assistant can retrieve the relevant portion without asking the same questions again.

Examples:

- If a user tells one assistant, “Call me Hippo,” other authorized assistants inherit that global preference.
- If Codex investigates a development problem, Claude Code can continue from the recorded findings, decisions, file changes, test results, and next action.
- If one travel assistant researches flights, another can inherit the dates, constraints, shortlist, rejection reasons, and current booking state while refreshing volatile prices and availability.
- A business can create a shared workspace in which employees and authorized agents share project decisions, procedures, research, and work traces without exposing members’ private memories.

The system is not merely a vector database. It combines:

1. An immutable evidence and work-trace ledger.
2. Working memory for active activities.
3. Semantic memory for stable facts and preferences.
4. Episodic memory for contextual experiences.
5. Procedural memory for reusable workflows and learned strategies.
6. A temporal knowledge graph.
7. Tenant, workspace, entity, and client-level authorization.
8. Encryption and optional end-to-end encrypted operation.
9. MCP, REST, SDK, CLI, browser, and tool-specific adapters.

The recommended implementation reuses existing systems behind replaceable interfaces:

- **Graphiti** for temporal knowledge-graph construction and retrieval.
- **Mem0 OSS and Hindsight** as the first semantic-memory engines to benchmark.
- **Cognee** as a broader alternative to benchmark against the composed stack.
- **PostgreSQL** as the authoritative metadata, event, policy, and memory database.
- **Rust** for the portable core server, worker, CLI, local E2EE gateway, authorization, and synchronization engine.
- **Cloudflare Workers, Durable Objects, Queues, Workflows, Vectorize, R2, and Hyperdrive** as an optional distributed edge and hosted platform.

No third-party memory library owns the canonical user identity, workspace membership, encryption keys, authorization decisions, or immutable evidence ledger.

The complete core platform will be open source and independently deployable. Cloudflare is the recommended hosted reference architecture, not a mandatory dependency. Operators can bring their own database, graph engine, semantic-memory engine, vector store, object store, model provider, authentication provider, and credentials.

---

## 2. Product vision

> Provide every person and organization with a secure, portable memory layer that authorized AI tools can read and improve, enabling work to continue across assistants, models, applications, devices, and time.

The product should feel like a human-centered “memory operating system,” while improving on biological memory through provenance, explicit uncertainty, inspection, reliable correction, controlled sharing, and deletion.

### 2.1 Product principles

1. **User ownership:** Users can inspect, export, correct, archive, and delete their memories.
2. **Capture once, reuse everywhere:** Authorized tools search memory before asking repeated questions.
3. **Contextual disclosure:** A client receives the minimum relevant context, not the complete user profile.
4. **Evidence before inference:** Generated summaries and agent observations never become unquestionable truth.
5. **Specific overrides general:** Task instructions override entity, domain, and global defaults.
6. **Memory does not authorize action:** Knowing a payment method or deployment procedure does not grant permission to use it.
7. **Current reality remains authoritative:** Project files, booking systems, prices, policies, and other volatile external data must be refreshed.
8. **Privacy by architecture:** Cross-user and cross-workspace leakage is treated as a critical security failure.
9. **Vendor independence:** Memory must remain portable across models, memory engines, clouds, and graph stores.
10. **Human control:** Agents may propose important memories; users or authorized workspace roles govern their acceptance.
11. **Open-source deployability:** The complete core can run without the hosted service.
12. **Bring your own infrastructure:** Providers are selected through configuration and replaceable adapters.
13. **Universal attachment:** Users can connect the memory system to CLIs, applications, bots, assistants, coding tools, agents, and custom services.
14. **Compose, do not reinvent:** Reuse proven memory, graph, storage, cryptography, identity, and infrastructure systems behind stable interfaces.

---

## 3. Product scope

### 3.1 Initial scope

#### Personal

- Identity and preferred form of address
- Pronouns, languages, timezone, and accessibility needs
- Communication and response preferences
- Global AI instructions
- Long-term goals and interests
- User-confirmed observations
- Private relationships and roles

#### Development by project

- Organizations, projects, repositories, branches, and environments
- Architecture and technology choices
- Setup, build, test, and deployment procedures
- Coding preferences and project instructions
- Agent conversations and work traces
- Commands, file reads, file changes, tests, builds, and deployments
- Questions already answered
- Decisions, alternatives, and rejection reasons
- Active tasks, checkpoints, blockers, and handoffs
- Learned successful and failed strategies

#### Travel

- Trips, travellers, destinations, dates, budgets, and constraints
- Durable travel preferences
- Flight, hotel, transport, and activity research
- Search criteria, shortlists, and rejection reasons
- Itineraries and booking states
- Volatile information with freshness requirements
- Protected traveller and payment references

### 3.2 Later domains

- Research and reading
- Design and creative work
- Shopping
- Food
- Health and wellness
- Finance
- Business operations
- Relationships and communication
- Education
- Home administration
- Events

### 3.3 Explicit non-goals for the first release

- Fully autonomous purchases, deployments, or irreversible actions
- General-purpose multi-agent orchestration
- Replacing source-control, issue-tracking, CRM, booking, or document systems
- Storing secrets directly in ordinary memory
- Automatically treating every captured event as useful long-term memory
- Building a novel vector database, graph database, or cryptographic primitive
- Requiring Cloudflare, PostgreSQL, Graphiti, Mem0, or any other single provider

---

## 4. Users and workspace model

### 4.1 User types

- Individual user
- Workspace owner
- Workspace administrator
- Workspace editor
- Workspace viewer
- Guest
- AI client
- Service account

### 4.2 Workspace types

#### Personal workspace

Created automatically for each user. It contains private identity, preferences, projects, trips, and activities.

#### Shared workspace

Created by a business, team, household, or group. It contains shared entities, activities, memories, procedures, and decisions.

Private memory must never become shared automatically. Sharing requires an explicit copy, promotion, or proposal operation.

### 4.3 Authorization hierarchy

```text
Workspace
└── Domain
    └── Entity
        └── Activity
            └── Memory / Event / Artifact
```

Permissions can be granted at any level and inherited downward, subject to explicit denial and sensitivity policies.

### 4.4 Initial roles

| Role | Capabilities |
|---|---|
| Owner | Workspace control, membership, recovery, policies |
| Administrator | Members, AI clients, domain policies |
| Editor | Read and propose/write permitted memories |
| Viewer | Read permitted context |
| Guest | Restricted entity/activity access |
| AI client | Explicit machine scopes only |

AI clients should receive granular scopes such as:

```text
profile:read-basic
profile:read-preferences
memory:propose
memory:read
activity:checkpoint
trace:write
development:read
travel:read
action:request
```

### 4.5 Product experience levels

The same core must serve three audiences without exposing unnecessary technical complexity.

#### Managed experience

For non-technical individuals and small teams:

```text
Create account
→ Create private memory
→ Connect assistants
→ Review requested access
→ Start using memory
```

The managed product operates storage, synchronization, updates, backups, and recovery guidance.

#### Personal-device experience

For a user running the system on a laptop, desktop, home server, or Mac mini:

```text
Install desktop application
→ Choose “Run on this device”
→ Create recovery method
→ Connect assistants
→ Add other devices by QR or trusted-device approval
```

The desktop application manages the local daemon, encrypted database, graph/search services, backups, integrations, health checks, and signed updates. A terminal is not required.

#### Advanced and organizational experience

Developers and businesses can use the CLI, containers, environment variables, customer cloud accounts, custom providers, Kubernetes, SSO, and advanced policy controls.

All experience levels use the same canonical schemas and compatibility protocol.

---

## 5. Core domain model

The five universal primitives are:

```text
Person → Entity → Activity → Memory → Action
```

### 5.1 Entity

A durable subject around which knowledge accumulates.

Examples: person, organization, project, repository, trip, destination, flight, document, concept.

### 5.2 Activity

A goal-directed process that may continue across tools and agents.

Common properties:

- Objective
- Current state
- Constraints
- Questions and authoritative answers
- Research performed
- Options considered
- Decisions and reasons
- Actions completed
- Blockers
- Next actions

### 5.3 Event

An immutable statement that something occurred:

- User issued an instruction
- Agent inspected a file
- Command executed
- Test succeeded
- Flight option observed
- User corrected a memory

Events are evidence; they are not automatically accepted memories.

### 5.4 Memory

A current interpretation derived from one or more events or explicitly entered by a user.

Required properties:

```text
workspace_id
subject
predicate/type
value/content
domain
entity/activity scope
authority
confidence
sensitivity
valid_from / valid_until
source evidence
status
version
```

### 5.5 Action

An attempted external side effect with a separate authorization and execution lifecycle:

```text
Proposed → Authorized → Started → Pending → Succeeded/Failed/Unknown → Reversed
```

---

## 6. Memory taxonomy

| Memory type | Example | Expected lifecycle |
|---|---|---|
| Identity | “Call me Hippo” | Durable, user-authoritative |
| Preference | “Prefer aisle seats” | Durable but overridable |
| Instruction | “Never deploy without approval” | Strong constraint |
| Semantic fact | “Otto uses PostgreSQL” | Evidence-backed and versioned |
| Episode | “Authentication tests passed yesterday” | Contextual and temporal |
| Procedure | “How to release Otto mobile” | Versioned workflow |
| Working memory | Current objective and next step | Short-lived/checkpointed |
| Observation | “May prefer visual explanations” | Provisional |
| Goal | “Build a universal memory layer” | Active, paused, or completed |
| Decision | “Use Cloudflare for the edge layer” | Durable with rationale |
| Evidence | Transcript, file diff, receipt | Immutable reference |
| Secret reference | `vault://payment/preferred` | Never contains secret value |

### 6.1 Authority order

1. Current explicit user instruction
2. Explicit user-confirmed memory
3. Previous explicit user statement
4. Authorized workspace decision or trusted system record
5. Repeated agent observation
6. Single agent observation
7. External content
8. Agent speculation

Scope is evaluated separately:

```text
task > activity > entity > domain > workspace > global personal
```

---

## 7. Core use cases

### 7.1 Universal preference continuity

The user tells one assistant, “Call me Hippo.” The system stores a global, explicit identity preference. Any subsequently authorized assistant retrieves it as part of the personal bootstrap context.

### 7.2 Development handoff

Codex identifies an authentication race, changes two files, runs unit tests, and pauses before integration testing. Claude Code opens the repository, validates the branch and file hashes, retrieves the checkpoint, and continues with integration tests.

### 7.3 Repeated-question avoidance

Before asking “Which package manager should I use?”, an agent searches project memory. A confirmed project answer, `pnpm`, is returned with evidence and validity information.

### 7.4 Travel handoff

One assistant searches Delhi–Tokyo flights and records constraints and a shortlist. Another assistant retrieves the trip activity, refreshes price and availability, and continues comparing baggage and cancellation terms.

### 7.5 Shared company brain

Workspace members and agents retrieve shared architecture decisions and operational procedures. Private employee preferences and observations remain outside the workspace.

### 7.6 Correcting memory

The user corrects an outdated preference. The current memory is superseded, dependent summaries are invalidated, indexes are updated, and original evidence remains in restricted history.

### 7.7 Forgetting

The user deletes an entity. The platform removes or tombstones canonical records according to policy, deletes vectors and graph projections, expires caches, removes artifacts, and schedules encrypted-backup expiry.

---

## 8. Functional requirements

### 8.1 Capture

- Accept explicit memories, messages, events, files, and tool traces.
- Support MCP, REST, SDK, CLI, browser, Git, IDE, and agent-hook ingestion.
- Detect likely credentials and sensitive personal data before persistence.
- Preserve raw evidence separately from extracted memories.
- Allow configurable capture levels: minimal, standard, complete, excluded.
- Support incognito/no-capture mode.

### 8.2 Extraction and consolidation

- Generate candidate facts, preferences, procedures, entities, and relationships.
- Distinguish user statements, external evidence, and agent inference.
- Deduplicate semantically equivalent candidates.
- Detect contradictions and scope differences.
- Consolidate repeated episodes into semantic memory.
- Never promote high-impact inferred memories without policy approval.

### 8.3 Retrieval

- Combine exact, full-text, vector, temporal, and graph retrieval.
- Filter by workspace, user, client, domain, entity, activity, sensitivity, and validity before disclosure.
- Rank by relevance, authority, scope, confidence, freshness, and graph proximity.
- Return evidence references and uncertainty.
- Compile token-bounded client-specific context.
- Precompute common profile, project, trip, and activity bootstrap packages.

### 8.4 Working memory and handoff

- Track objective, state, plan, findings, assumptions, blockers, and next actions.
- Create checkpoints at task boundaries and before context compaction.
- Validate development checkpoints against current Git and filesystem state.
- Validate travel checkpoints against current provider state.
- Detect circular or non-progressing handoffs.

### 8.5 Knowledge graph

- Support typed nodes and relationships.
- Maintain event time and system ingestion time.
- Support validity windows and supersession.
- Resolve aliases without unsafe automatic merges.
- Retrieve neighbourhoods, paths, communities, and relevant subgraphs.
- Maintain strict workspace namespaces.

### 8.6 Workspace collaboration

- Invite, remove, and suspend members.
- Grant roles and entity-level permissions.
- Create shared memory proposals.
- Preserve authorship and decision ownership.
- Rotate encryption keys after membership changes.
- Maintain read/write/access audit trails.

### 8.7 Interoperability and portability

- Publish an implementation-independent memory API.
- Publish a discoverable Memory Provider Protocol with capability negotiation, scoped account linking, context resolution, memory proposals, activity checkpoints, disclosure receipts, and conformance tests.
- Offer MCP, REST, TypeScript, Python, and CLI clients.
- Support remote HTTP MCP and local stdio MCP transports.
- Support coding tools, desktop/mobile applications, web applications, bots, assistants, agent frameworks, and custom services.
- Let users connect an existing deployment using OAuth, an API token, or a local credential profile.
- Generate tool-specific configuration while keeping canonical memory provider-independent.
- Export JSONL, Markdown, encrypted archive, and graph formats.
- Import common chat exports and supported third-party memory formats.
- Keep provider-specific identifiers out of canonical identity.
- Separate channel adapters from agent adapters so that WhatsApp, iMessage, web, CLI, and IDE transports do not become the user identity or own canonical memory.
- Classify every connection using verified compatibility tiers: native provider, MCP/tool/plugin, user-controlled gateway, explicit share/context card, import/export, or unsupported.
- Do not claim transparent support for a closed bot merely because it is reachable through WhatsApp or iMessage.
- Preserve coexistence with bot-local memory: central memory owns portable confirmed facts and continuity, while bot-local memory retains ephemeral execution state and provider-specific caches.
- Apply conflict precedence in this order: current explicit instruction, scoped confirmed central memory, global confirmed central memory, authorized shared memory, recent bot observation, then model default.

Detailed design: [Bot and Platform Integration Architecture](BOT_AND_PLATFORM_INTEGRATION_ARCHITECTURE.md).

### 8.8 Open-source installation and bring-your-own infrastructure

- Publish the core server, setup CLI, SDKs, schemas, migrations, provider contracts, and official adapters under a permissive open-source license.
- Provide Docker Compose for a complete single-machine deployment.
- Add Cloudflare, Terraform/Pulumi, and Kubernetes deployment templates.
- Support hosted SaaS, self-hosted cloud, private VPC, on-premises, and local-only operation from the same codebase.
- Accept credentials through environment variables, secret files, container secrets, or external secret managers.
- Validate provider configuration and connectivity before applying migrations.
- Include upgrade, backup, restore, export, import, and diagnostic commands.
- Make telemetry optional and prevent memory content from entering telemetry.
- Support air-gapped deployments with local models and locally hosted dependencies.
- In local and self-hosted deployments, connect directly from the operator's environment to configured providers; never route provider credentials or plaintext memory through a vendor-operated relay.
- Keep the framework fully functional with outbound telemetry and vendor network access disabled.
- Make update checks optional and ensure they transmit only the installed version and platform when enabled.

### 8.9 Setup and integration CLI

The primary setup experience must be both interactive and scriptable:

```text
rembrane init
rembrane configure
rembrane doctor
rembrane migrate
rembrane server start
rembrane worker start
rembrane providers list
rembrane providers test
rembrane connect mcp
rembrane connect codex
rembrane connect claude-code
rembrane connect cursor
rembrane connect bot
rembrane disconnect
rembrane backup
rembrane restore
rembrane export
rembrane import
```

`rembrane init` should:

1. Select local, Docker, Cloudflare, Kubernetes, or custom deployment.
2. Select database, graph, vector, artifact, model, embedding, and authentication providers.
3. Collect credential references without printing or persisting plaintext secrets.
4. Test connectivity and required capabilities.
5. Generate configuration and deployment files.
6. Run or print required migrations.
7. Create the first owner and personal workspace.
8. Detect supported AI tools and offer integrations.
9. Display an auditable plan before making changes.

Every interactive operation must also support flags and configuration files for automation and CI.

### 8.10 Non-technical user experience

- Provide a desktop application and managed web experience requiring no database, graph, model, or cryptography knowledge.
- Use plain-language actions such as “Remember everywhere,” “Only for this trip,” “Share with Otto,” and “Forget this.”
- Hide provider credentials, graph configuration, vector indexes, and infrastructure terminology behind an optional advanced view.
- Offer a connection marketplace for supported assistants, coding tools, browsers, applications, and bots.
- Before connecting a tool, explain what it can read, write, and never access.
- Present uncertain agent observations in a memory approval inbox.
- Let users accept an observation globally, limit it to an entity/activity, correct it, or reject it.
- Provide visible capture state and one-click pause/incognito mode.
- Provide search and inspection through questions such as “What do you remember about me?” and “Why did you use this?”
- Guide users through adding a trusted device and testing recovery during onboarding.
- Clearly warn that strict-E2EE data can become unrecoverable if all devices and recovery material are lost.
- Provide safe defaults; advanced provider and permission settings remain optional.

Example connection card:

```text
Claude Code wants:
✓ Read development preferences
✓ Read and checkpoint Project Otto
✗ No travel access
✗ No private relationship access

[Connect] [Customize]
```

Example memory inbox:

```text
An assistant noticed:
“You may prefer aisle seats.”

[Remember globally]
[Only for Japan Trip]
[Not true]
```

---

## 9. Non-functional requirements

### 9.1 Security

- Zero cross-tenant disclosure in automated isolation tests.
- Deny-by-default authorization.
- Every request bound to authenticated user, workspace, client, and purpose.
- RLS on every tenant-owned PostgreSQL table.
- No raw memory content in ordinary logs.
- Secret references instead of secret values.
- Signed or integrity-protected event records.
- Idempotency for every retriable write or external action.
- Regular penetration testing focused on prompt injection, memory poisoning, and privilege escalation.

### 9.2 Privacy

- Personal and workspace memory remain separate.
- Data minimization and configurable retention.
- Explicit disclosure log: which client received which memory IDs.
- Export, correction, deletion, and account closure.
- No model training on user data by default.
- Configurable processing providers and local-model support.

### 9.3 Performance targets

These are initial engineering targets, excluding model inference:

| Operation | p95 target |
|---|---:|
| Cached profile/bootstrap | < 50 ms |
| Explicit preference lookup | < 75 ms |
| Event/checkpoint acknowledgement | < 150 ms |
| Exact/entity search | < 150 ms |
| Hybrid retrieval | < 400 ms |
| Graph neighbourhood retrieval | < 400 ms |
| Background memory/graph projection | < 10 seconds |

### 9.4 Availability and durability

- No event acknowledged before durable persistence.
- At-least-once processing with idempotent consumers.
- Dead-letter queues and replay tooling.
- Point-in-time database recovery.
- Encrypted artifact replication and tested restoration.
- Graceful operation if graph, vector, or LLM providers are temporarily unavailable.

---

## 10. Existing tool and library evaluation

This review covers major active and relevant systems, not every experimental repository.

### 10.1 Mem0 OSS

**Fit:** Good semantic-memory component.

Strengths:

- Apache 2.0.
- Python and TypeScript support.
- Configurable LLM, embedding, vector, history, and reranking providers.
- Broad agent-framework integrations.
- Familiar `add`, `search`, update, history, and delete lifecycle.

Limitations:

- Graph memory was removed from the current OSS SDK and is now a managed-platform feature.
- Its internal memory schema is not sufficient for our event ledger, action authorization, E2EE, or workspace governance.

**Decision:** Benchmark and likely adopt behind `SemanticMemoryEngine`; never use as canonical storage.

Sources: [Mem0 repository](https://github.com/mem0ai/mem0), [OSS configuration](https://github.com/mem0ai/mem0/blob/main/docs/open-source/configuration.mdx), [OSS graph migration](https://github.com/mem0ai/mem0/blob/main/docs/migration/oss-v2-to-v3.mdx).

### 10.2 Mem0 Platform/OpenMemory

**Fit:** Rapid managed prototype and interoperability reference.

Strengths:

- Hosted MCP and entity-scoped memories.
- Managed extraction, retrieval, and graph-enhanced ranking.

Limitations:

- Hosted processing conflicts with strict E2EE.
- Graph implementation and platform optimizations are proprietary.
- Less control over canonical tenancy, keys, deletion mechanics, and data plane.

**Decision:** Do not use as the product’s authoritative hosted data plane; retain optional import/export integration.

### 10.3 Graphiti

**Fit:** Best initial temporal knowledge-graph engine.

Strengths:

- Apache 2.0.
- Temporal episodes, facts, validity windows, and changing relationships.
- Custom node and edge types.
- Namespacing using `group_id`.
- Neo4j, FalkorDB, and Amazon Neptune backends.
- Hybrid graph and semantic retrieval.

Limitations:

- Python service in an otherwise TypeScript-heavy platform.
- Not a complete workspace, identity, permission, or E2EE product.
- LLM-based entity resolution requires cost and quality controls.

**Decision:** Adopt behind `KnowledgeGraphEngine`, using a workspace-derived namespace that clients cannot choose directly.

Sources: [Graphiti repository](https://github.com/getzep/graphiti), [namespacing](https://help.getzep.com/graphiti/core-concepts/graph-namespacing), [Zep/Graphiti deployment comparison](https://help.getzep.com/zep-vs-graphiti).

### 10.4 Zep Cloud

**Fit:** Managed context graph for customers preferring SaaS/BYOC.

Strengths:

- Managed temporal context infrastructure.
- Production graph operations without self-hosting Graphiti.

Limitations:

- Adds a critical memory vendor and data processor.
- Not appropriate for the strict E2EE mode.

**Decision:** Possible enterprise/BYOC adapter, not default.

### 10.5 Cognee

**Fit:** Strongest integrated graph-first alternative.

Strengths:

- Apache 2.0.
- Graph, vector, session, code, and document memory.
- Multi-tenant authentication and ACL concepts.
- MCP, Codex, Claude Code, REST, Python, TypeScript, and Rust surfaces.
- Local-model and self-hosted operation.
- Explicit “Company Brain” use case.

Limitations:

- Broad platform overlap with our product.
- Production single-Postgres graph functionality is described as licensed while the repository exposes a demo path.
- Adopting its complete model would constrain our canonical schema and E2EE design.

**Decision:** Mandatory benchmark against Mem0 + Graphiti; consider using selected ingestion and code-memory components through an adapter.

Sources: [Cognee repository](https://github.com/topoteretes/cognee), [ACL](https://docs.cognee.ai/core-concepts/permissions-system/acl), [API](https://docs.cognee.ai/api-reference/introduction).

### 10.6 Hindsight

**Fit:** Promising semantic/reflective memory engine.

Strengths:

- MIT licensed OSS engine.
- Retain, recall, and reflect architecture.
- Self-hosted, managed, and enterprise deployment options.
- MCP and coding-agent integrations.
- Designed to learn from accumulated memory rather than only retrieve nearest chunks.

Limitations:

- Younger operational ecosystem than PostgreSQL-centric application libraries.
- Needs independent evaluation for tenant enforcement, deletion, provenance, latency, and multilingual behaviour.

**Decision:** Benchmark directly against Mem0 OSS for semantic extraction, recall quality, and reflection.

Sources: [Hindsight repository](https://github.com/vectorize-io/hindsight), [deployment options](https://docs.hindsight.vectorize.io/), [research paper](https://arxiv.org/abs/2512.12818).

### 10.7 Letta

**Fit:** Optional stateful-agent adapter.

Strengths:

- Agent-managed memory blocks.
- Blocks can be shared across multiple agents and made read-only.
- Self-hosted app server and multiple client protocols.

Limitations:

- Agent identity is primary; our product makes the person/workspace primary.
- A complete agent runtime is unnecessary for clients that only need memory.

**Decision:** Support as an integration target; do not use as the core.

Sources: [stateful agents](https://docs.letta.com/concepts/stateful-agents), [shared memory blocks](https://docs.letta.com/v1-sdk/memory/memory-blocks), [self-hosting](https://docs.letta.com/self-hosting/app-server).

### 10.8 LangMem and LangGraph memory

**Fit:** Useful extraction/consolidation patterns for LangGraph applications.

Strengths:

- Separates semantic profiles, episodic examples, and procedural instructions.
- Supports hot-path and background memory formation.
- LangGraph stores provide cross-thread persistence.

Limitations:

- Closely tied to the LangChain/LangGraph ecosystem.
- Not an independent multi-user memory service.

**Decision:** Reuse conceptual patterns and offer an adapter; avoid core dependency.

Source: [LangMem conceptual guide](https://langchain-ai.github.io/langmem/concepts/conceptual_guide/).

### 10.9 Supermemory

**Fit:** Integration and performance benchmark.

Strengths:

- TypeScript-oriented memory/context platform.
- MCP and coding-tool integrations.
- Local/self-hosting option.
- Connectors for common content sources.

Limitations:

- Hosted and self-hosted capability/licensing boundaries require commercial verification.
- It does not replace our workspace encryption and governance layer.

**Decision:** Benchmark retrieval latency and integration UX; provide migration compatibility if demand exists.

Sources: [Supermemory repository](https://github.com/supermemoryai/supermemory), [MCP server](https://github.com/supermemoryai/supermemory/blob/main/apps/mcp/README.md), [self-hosting](https://github.com/supermemoryai/supermemory/blob/main/apps/docs/self-hosting/overview.mdx).

### 10.10 Memobase

**Fit:** Personal-profile extraction reference.

Strengths:

- Focused on evolving user profiles and event timelines.
- Self-hosted option.

Limitations:

- Narrower than entity/activity/work-trace continuity.
- Does not supply our knowledge graph, collaboration, and action-security model.

**Decision:** Study profile schema and benchmark personal preference extraction only.

Source: [Memobase repository](https://github.com/memodb-io/memobase).

### 10.11 MemoryOS and MemOS

**Fit:** Research and local-memory references.

Strengths:

- Hierarchical short-, mid-, and long-term memory concepts.
- Local-first and MCP approaches in current implementations.
- MemOS includes graph, vector, and multi-agent memory ambitions.

Limitations:

- Rapidly evolving research-oriented projects.
- Production multi-tenant governance, cryptography, and operations require independent validation.

**Decision:** Track and test selected datasets, but do not base the first production core on them.

Sources: [MemoryOS repository](https://github.com/BAI-LAB/MemoryOS), [MemoryOS paper](https://aclanthology.org/2025.emnlp-main.1318.pdf), [MemOS repository](https://github.com/MemTensor/MemOS).

### 10.12 LlamaIndex, Semantic Kernel, and framework memory

**Fit:** Application adapters.

Strengths:

- Mature agent/RAG ecosystems and vector-store abstractions.
- Useful for applications already built on the respective framework.

Limitations:

- Their memory abstractions are framework-scoped rather than a universal user-owned service.
- Some memory APIs remain experimental or preview.

**Decision:** Build adapters after the MCP, REST, and TypeScript SDK surfaces stabilize.

Sources: [Semantic Kernel agent memory](https://learn.microsoft.com/en-us/semantic-kernel/frameworks/agent/agent-memory), [vector-store abstractions](https://learn.microsoft.com/en-us/semantic-kernel/concepts/vector-store-connectors), [LlamaIndex Memory example](https://docs.llamaindex.ai/en/stable/examples/tools/order_completion_agent_with_artifact_editor/).

### 10.13 Evaluation conclusion

No evaluated tool satisfies all requirements simultaneously:

- Human/user-centered canonical identity
- Immutable work trace
- Personal and shared workspaces
- Fine-grained multi-tenant authorization
- Temporal typed graph
- Cross-agent interoperability
- E2EE with shared workspace key management
- User review and correction
- Action authorization
- Complete portability

Therefore, the platform should compose existing memory engines rather than select one as the entire product.

---

## 11. Recommended engine interfaces

```typescript
interface SemanticMemoryEngine {
  extract(input: ExtractionInput): Promise<MemoryCandidate[]>;
  consolidate(input: ConsolidationInput): Promise<MemoryCandidate[]>;
  search(input: SemanticQuery): Promise<SemanticResult[]>;
  deleteScope(input: DeleteScope): Promise<void>;
}

interface KnowledgeGraphEngine {
  ingest(input: GraphIngestion): Promise<GraphMutationResult>;
  search(input: GraphQuery): Promise<GraphResult>;
  neighbours(input: NeighbourQuery): Promise<GraphResult>;
  paths(input: PathQuery): Promise<GraphResult>;
  deleteScope(input: DeleteScope): Promise<void>;
}

interface EmbeddingEngine {
  embed(input: EmbeddingInput): Promise<EmbeddingResult>;
}

interface CanonicalStore {
  transact<T>(operation: CanonicalOperation<T>): Promise<T>;
  migrate(): Promise<MigrationResult>;
  health(): Promise<ProviderHealth>;
}

interface VectorStore {
  upsert(input: VectorUpsert): Promise<void>;
  search(input: VectorQuery): Promise<VectorResult[]>;
  deleteScope(input: DeleteScope): Promise<void>;
}

interface ArtifactStore {
  put(input: ArtifactWrite): Promise<ArtifactReference>;
  get(input: ArtifactRead): Promise<ArtifactStream>;
  deleteScope(input: DeleteScope): Promise<void>;
}

interface ModelProvider {
  generate(input: ModelRequest): Promise<ModelResponse>;
  health(): Promise<ProviderHealth>;
}

interface ContextCompiler {
  compile(input: ContextRequest): Promise<ContextPackage>;
}
```

Initial adapters:

```text
SemanticMemoryEngine
├── Mem0 OSS
├── Hindsight
├── Cognee
└── Native baseline

KnowledgeGraphEngine
├── Graphiti
├── Cognee
└── PostgreSQL shallow graph

CanonicalStore
├── PostgreSQL
└── SQLite / SQLCipher

VectorStore
├── pgvector
├── Cloudflare Vectorize
├── Qdrant
├── Weaviate
├── Pinecone
└── local embedded index

ArtifactStore
├── Cloudflare R2
├── Amazon S3
├── S3-compatible storage
└── local filesystem
```

These provider interfaces are part of the public compatibility contract. Vendor SDKs must remain inside provider packages rather than leaking into core domain code.

---

## 12. Privacy and encryption architecture

### 12.1 Privacy modes

#### Managed-private mode

- TLS in transit.
- Provider and application encryption at rest.
- Per-workspace data-encryption keys.
- The authorized service can decrypt temporarily for extraction and retrieval.
- Best search performance and simplest multi-device experience.

This is not strict E2EE.

#### End-to-end encrypted mode

- Plaintext exists only on authorized user devices or customer-controlled gateways.
- Local gateway performs extraction, embedding, graph updates, and retrieval.
- Cloud stores encrypted events, snapshots, artifacts, and synchronization messages.
- Only selected context is disclosed to the AI provider chosen for a request.

Hosted vector and graph services cannot directly search encrypted content without weakening the E2EE claim. E2EE mode therefore requires local or customer-controlled searchable indexes.

E2EE mode does not conceal every operational field. Workspace and principal
identifiers, membership and invitation state, roles, key identifiers, record
versions, timestamps, and other minimum routing/authorization metadata may be
visible to the component enforcing access. Deployments requiring metadata
confidentiality must keep that component local or inside the customer-controlled
boundary and may additionally use whole-database encryption.

#### Enterprise-private mode

- Customer-owned cloud/VPC or on-premises deployment.
- Customer-managed databases, graph, models, keys, backups, and network policy.
- Our control-plane involvement is optional and metadata-minimized.

### 12.2 Device and workspace keys

- Each device has an encryption and signing identity.
- Each workspace has a versioned data-encryption key.
- Workspace keys are wrapped for authorized member devices.
- Membership removal triggers future-key rotation.
- Historical re-encryption is configurable.
- Losing every recovery mechanism may make strict E2EE data unrecoverable; the UI must communicate this clearly.

For group key agreement, use an audited implementation of Messaging Layer Security rather than inventing group cryptography. MLS is standardized in RFC 9420 and designed for asynchronous groups with forward-secrecy and post-compromise-security goals. [RFC 9420](https://www.rfc-editor.org/info/rfc9420/) and [MLS architecture](https://www.rfc-editor.org/rfc/rfc9750.html).

Use established cryptographic libraries such as libsodium for authenticated encryption, sealed key delivery, and signatures. [Libsodium documentation](https://doc.libsodium.org/doc) and [sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes).

Local databases should use OS key storage plus SQLCipher or equivalent encrypted SQLite. SQLCipher adds transparent AES-256 database-file encryption. [SQLCipher](https://github.com/sqlcipher/sqlcipher).

### 12.3 Important revocation limitation

Removing a member prevents future authorized access but cannot force that member or an AI provider to erase plaintext already disclosed. The system must minimize disclosure and retain immutable access receipts.

---

## 13. Recommended technology stack

The following is the maintained reference stack. Operators can replace components through provider adapters without changing domain or application code.

### 13.1 Cloud and application layer

| Concern | Choice |
|---|---|
| Portable core API and MCP | Rust + Axum + official MCP Rust SDK |
| Optional edge gateway | Cloudflare Workers |
| Per-user coordination | Durable Objects |
| Long-running jobs | Cloudflare Workflows |
| Background events | Cloudflare Queues + DLQ |
| Artifacts and encrypted traces | Cloudflare R2 |
| Semantic index | Vectorize in managed mode |
| External DB pooling | Hyperdrive |
| Web application | Next.js on Cloudflare |
| Core workspace | Cargo workspace |
| Web/JS workspace | pnpm + Turborepo |
| Validation/contracts | Serde + JSON Schema/OpenAPI; Zod in TypeScript clients |
| Infrastructure | Pulumi or Terraform plus Wrangler |

Cloudflare Durable Objects provide private, strongly consistent storage per object, making one object per user or active workspace useful for coordination and working state. [Durable Objects SQLite](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

Cloudflare Queues provides at-least-once delivery, so all jobs require idempotency keys. [Queues delivery guarantees](https://developers.cloudflare.com/queues/reference/delivery-guarantees/).

### 13.2 Canonical persistence

| Concern | Choice |
|---|---|
| Canonical database | Managed PostgreSQL |
| ORM/query layer | Drizzle plus reviewed SQL |
| Semantic fallback | pgvector |
| Exact search | PostgreSQL full-text search |
| Tenant isolation | PostgreSQL RLS |
| Immediate shallow graph | PostgreSQL entity/edge tables |
| Temporal graph | Graphiti with Neo4j initially |
| Cache | Durable Object state; Redis only if later justified |

PostgreSQL remains authoritative for users, workspaces, memberships, events, memory versions, policies, consent, actions, and audit metadata.

### 13.3 Memory-processing services

| Concern | Initial choice |
|---|---|
| Candidate extraction | Mem0 OSS and Hindsight benchmark winner |
| Temporal graph | Graphiti |
| Baseline engine | Native deterministic rules |
| Alternative integrated engine | Cognee adapter |
| Model routing | Provider-neutral internal gateway |
| Local/private models | Ollama or customer-selected runtime |

Every extraction stores:

- Engine and version
- Model and version
- Prompt/schema version
- Input evidence IDs
- Output candidate IDs
- Confidence
- Processing location

### 13.4 Local E2EE gateway

| Concern | Choice |
|---|---|
| Desktop daemon | Rust core with narrow Tauri/TypeScript UI bindings |
| Local database | SQLite + SQLCipher |
| Local graph | SQLite edge tables initially |
| Local vector search | Embedded vector index selected after benchmark |
| Cryptography | Audited MLS implementation + libsodium |
| Device key storage | macOS Keychain, Windows DPAPI, Linux Secret Service |
| Sync | Encrypted event envelopes through Workers/R2 |

Implement the MVP gateway in Rust so cryptography, synchronization, local storage, and authorization share the same trusted core as the self-hosted server. TypeScript is limited to the desktop and web presentation layers.

### 13.5 Existing components versus platform-owned components

```text
Reuse existing systems
├── Mem0 / Hindsight / Cognee: semantic memory
├── Graphiti: temporal knowledge graph
├── PostgreSQL: transactional persistence
├── pgvector / Vectorize: semantic indexing
├── OpenMLS: shared-workspace group key management
├── libsodium: authenticated record and file encryption
├── SQLCipher: encrypted local database
├── OAuth/OIDC: authentication
└── Cloudflare: edge runtime, coordination, jobs, and sync

Build in this platform
├── canonical memory protocol
├── identity and workspace model
├── provider adapter contracts
├── provenance and authority rules
├── cross-agent continuity
├── context compiler
├── consent and action authorization
├── E2EE key orchestration
├── setup and integration CLI
└── migration and portability tooling
```

### 13.6 Supported deployment profiles

#### Cloudflare reference

```text
Workers + Durable Objects + Queues + Workflows
R2 + Vectorize
PostgreSQL through Hyperdrive
Graphiti + Neo4j
```

#### Docker Compose reference

```text
API + worker + web + MCP containers
PostgreSQL + pgvector
Graphiti + Neo4j
S3-compatible object storage
Optional local model runtime
```

#### Minimal local profile

```text
Desktop application or single server process
Tauri shell with Rust core for the graphical installer
SQLite + SQLCipher
Local artifact directory
Local vector index
SQLite graph tables
Optional local model endpoint
```

#### Custom/BYO profile

```text
Operator-supplied database
Operator-supplied graph and Graphiti endpoint
Operator-supplied Mem0/Hindsight/Cognee endpoint
Operator-supplied vector and object stores
Operator-supplied models and embeddings
Operator-supplied OIDC provider
Operator-supplied secret manager
```

### 13.7 Versioned configuration

```yaml
version: 1

deployment:
  mode: self_hosted
  public_url: https://memory.example.com

canonical_store:
  provider: postgres
  url_env: MEMORY_DATABASE_URL
  tenant_isolation: row_level_security

semantic_memory:
  provider: mem0
  mode: self_hosted
  base_url_env: MEM0_BASE_URL
  api_key_env: MEM0_API_KEY

knowledge_graph:
  provider: graphiti
  base_url_env: GRAPHITI_BASE_URL
  credentials_env: GRAPHITI_CREDENTIALS
  namespace_strategy: workspace_hmac

vector_store:
  provider: pgvector
  database_url_env: MEMORY_DATABASE_URL

artifact_store:
  provider: s3_compatible
  endpoint_env: MEMORY_OBJECT_ENDPOINT
  bucket_env: MEMORY_OBJECT_BUCKET
  access_key_env: MEMORY_OBJECT_ACCESS_KEY
  secret_key_env: MEMORY_OBJECT_SECRET_KEY

models:
  extraction:
    provider: openai_compatible
    base_url_env: MEMORY_LLM_BASE_URL
    api_key_env: MEMORY_LLM_API_KEY
    model_env: MEMORY_LLM_MODEL
  embeddings:
    provider: openai_compatible
    base_url_env: MEMORY_EMBEDDING_BASE_URL
    api_key_env: MEMORY_EMBEDDING_API_KEY
    model_env: MEMORY_EMBEDDING_MODEL

auth:
  provider: oidc
  issuer_env: MEMORY_OIDC_ISSUER
  client_id_env: MEMORY_OIDC_CLIENT_ID
```

Configuration precedence:

```text
CLI flags
> secret-file references
> environment variables
> deployment configuration
> safe defaults
```

Secrets must never be written into generated configuration unless the operator explicitly selects an encrypted secret file. `.env.example` files contain variable names and descriptions only.

### 13.8 Credential custody and secret locality

Credential ownership follows the selected deployment:

| Deployment | Where credentials live | Can the project operator access them? |
|---|---|---|
| Local laptop/Mac mini | OS keychain or protected local secret store | No |
| Local Docker | Docker secrets or mounted protected files | No |
| Customer Cloudflare | Cloudflare encrypted secrets in the customer's account | No |
| Customer AWS/Azure/GCP | Customer secret manager and customer IAM | No |
| Customer Kubernetes | Kubernetes secrets or external secret manager | No |
| Managed SaaS | Managed secret service under documented operator controls | Only where required for the managed service |

“Project operator” means the maintainers of the open-source framework or hosted control plane, not the owner of the deployment.

The setup CLI stores credential references, not credential values:

```yaml
canonical_store:
  provider: postgres
  url_env: MEMORY_DATABASE_URL

knowledge_graph:
  provider: graphiti
  api_key_env: GRAPHITI_API_KEY

semantic_memory:
  provider: mem0
  api_key_env: MEM0_API_KEY
```

Preferred secret sources:

```text
1. OS keychain or hardware-backed key storage
2. Customer cloud secret manager
3. Docker/Kubernetes secret mount
4. Protected secret file with restrictive permissions
5. Process environment variable
```

Environment variables are supported for portability, but they are not always the safest storage mechanism. The CLI must warn if credentials are passed directly as command-line arguments because shell history and process inspection may expose them.

Required guarantees:

- No credential values in logs, traces, crash reports, analytics, generated manifests, shell completions, or memory records.
- Configuration diagnostics display only provider name, credential source, fingerprint, and connection status.
- Provider requests go directly from the user's deployment to the selected provider.
- The hosted control plane does not need customer database, Graphiti, Mem0, model, or object-store credentials for customer-owned data planes.
- Secret rotation does not require rebuilding the application.
- Backups exclude credentials by default.
- Exported memory archives never contain infrastructure credentials.
- A `rembrane doctor --privacy` command reports every configured outbound
  endpoint origin and secret source while redacting endpoint credentials,
  paths, queries, fragments, and all secret values.
- A `CMEMORY_OFFLINE=true` mode blocks non-local provider access except explicitly allow-listed endpoints.

### 13.9 Provider contract

Every provider package must implement the relevant subset of:

```text
configure
validate
health
capabilities
migrate
read/write/delete
export
diagnostics
```

An operator can therefore use:

- Their own PostgreSQL or SQLite credentials.
- Their own Graphiti, Neo4j, FalkorDB, or compatible graph endpoint.
- Their own Mem0, Hindsight, Cognee, or future semantic-memory service.
- Their own Cloudflare, AWS, Azure, GCP, or S3-compatible storage.
- Their own hosted or local model and embedding credentials.
- Their own OIDC identity provider.

If a provider lacks a required capability, startup must reject the configuration or activate an explicit documented fallback. It must never silently weaken isolation, encryption, provenance, or deletion.

### 13.10 Open-source repository structure

```text
rembrane/
├── apps/
│   ├── api
│   ├── worker
│   ├── web
│   ├── mcp-server
│   └── cli
├── packages/
│   ├── core
│   ├── contracts
│   ├── crypto
│   ├── authorization
│   ├── context-compiler
│   ├── sdk-typescript
│   └── sdk-python
├── providers/
│   ├── canonical-postgres
│   ├── canonical-sqlite
│   ├── memory-mem0
│   ├── memory-hindsight
│   ├── memory-cognee
│   ├── graph-graphiti
│   ├── vector-pgvector
│   ├── vector-cloudflare
│   ├── artifacts-r2
│   ├── artifacts-s3
│   └── auth-oidc
├── integrations/
│   ├── generic-mcp
│   ├── codex
│   ├── claude-code
│   ├── cursor
│   ├── bots
│   └── browser-extension
├── domains/
│   ├── personal
│   ├── development
│   └── travel
└── deploy/
    ├── docker-compose
    ├── cloudflare
    ├── terraform
    └── helm
```

Recommended core license: Apache 2.0, subject to legal review. Each provider package must document its external dependencies and licensing terms.

---

## 14. Reference deployment architecture

```text
AI clients / browser / CLI / coding tools
                  │
                  ▼
      Cloudflare Worker API + MCP
      ├── OAuth/OIDC
      ├── client scopes
      ├── authorization
      ├── rate limits
      └── context compiler
                  │
          ┌───────┴────────┐
          ▼                ▼
 Per-user/workspace DO   Hyperdrive
 ├── locks                │
 ├── active state         ▼
 ├── versions        PostgreSQL
 └── hot context     ├── canonical events
                    ├── memories
                    ├── workspaces/RLS
                    ├── policies/audit
                    └── shallow graph
          │
          ├──────── Vectorize
          ├──────── R2
          └──────── Queues / Workflows
                              │
                ┌─────────────┴────────────┐
                ▼                          ▼
       Semantic-memory worker       Graphiti worker
       Mem0/Hindsight/native        Neo4j projection
```

For strict E2EE:

```text
Authorized device / customer gateway
├── decrypt
├── extract and consolidate
├── local vector + graph search
├── compile minimal context
└── encrypt synchronization envelopes
                  │
                  ▼
Cloudflare stores and synchronizes ciphertext only
```

---

## 15. Data isolation requirements

1. Every tenant-owned PostgreSQL row includes `workspace_id`.
2. Personal workspaces additionally bind to the owning user.
3. The request workspace is derived from verified authorization, never trusted from a payload alone.
4. The application DB role cannot bypass RLS.
5. Vector results are re-authorized against canonical memory IDs.
6. Graph namespaces are generated server-side from workspace IDs.
7. R2 keys use opaque workspace prefixes and never expose raw identity.
8. Queue messages carry signed internal workspace context and idempotency keys.
9. Caches include workspace, client, policy version, and memory version.
10. Automated tests attempt horizontal and vertical cross-tenant access on every API.

---

## 16. Retrieval design

```text
Context request
├── exact/entity lookup
├── PostgreSQL full-text search
├── vector search
├── temporal filtering
├── graph neighbourhood/path retrieval
└── active working-memory lookup
                 │
                 ▼
       authorization intersection
                 │
                 ▼
       merge, deduplicate, rerank
                 │
                 ▼
       token-bounded context package
```

Proposed ranking inputs:

```text
semantic relevance
exact-match strength
graph proximity
authority
scope specificity
confidence
freshness
contradiction penalty
sensitivity/disclosure cost
```

Volatile memories include `refresh_after`. Travel prices and availability should normally be refreshed before use; explicit identity preferences generally do not require external refresh.

---

## 17. Security and threat model

### Primary threats

- Cross-user or cross-workspace retrieval
- Prompt injection persisted into memory
- Malicious agents writing global instructions
- Poisoned shared workspace memory
- Sensitive context over-disclosed to an AI provider
- Credentials captured in traces
- Compromised client enumerating memories
- Duplicate purchases, messages, or deployments
- Removed workspace member retaining access
- Incorrect entity merges
- Stale memory driving unsafe action
- Logs, embeddings, caches, and backups bypassing deletion

### Required controls

- Treat all retrieved memory as untrusted data.
- Separate factual content from executable instructions.
- Limit client write authority by domain and memory type.
- Require approval for identity, governing instructions, sensitive inferences, and workspace-wide changes.
- Secret scanning before durable capture.
- Purpose-bound retrieval and disclosure budgets.
- Immutable provenance and access receipts.
- Rate limits and anomaly detection.
- Step-up authentication for exports, key recovery, membership changes, and destructive deletion.
- Independent authorization immediately before external actions.

---

## 18. API surface

```text
POST   /v1/events
POST   /v1/memory/proposals
POST   /v1/memory/confirm
POST   /v1/memory/search
POST   /v1/context/compile
POST   /v1/activities
POST   /v1/activities/{id}/checkpoint
POST   /v1/actions/request
POST   /v1/actions/{id}/confirm

GET    /v1/profile/bootstrap
GET    /v1/entities/{id}
GET    /v1/activities/{id}/resume
GET    /v1/memories/{id}/explain
GET    /v1/audit/disclosures

PATCH  /v1/memories/{id}
DELETE /v1/memories/{id}
POST   /v1/exports
POST   /v1/imports
```

Initial MCP tools:

```text
memory_get_context
memory_search
memory_remember
memory_propose
memory_correct
memory_forget
memory_explain
activity_start
activity_checkpoint
activity_resume
question_find_answer
question_record_answer
```

---

## 19. Distribution and connection experience

Supported installation entry points:

```text
npx @rembrane/cli init
pnpm dlx @rembrane/cli init
docker compose up
helm install
Cloudflare source deployment
prebuilt desktop/local gateway
```

The package name is provisional.

Connecting a tool:

```text
rembrane connect <tool>
├── detect the installed tool and configuration
├── display requested memory scopes
├── authenticate the user/workspace
├── write or print the proposed configuration
├── test search and checkpoint operations
└── provide a reversible disconnect command
```

The CLI must request confirmation before editing configuration owned by another application and preserve all unrelated settings.

Applications and bots can connect through OAuth-protected REST, remote MCP, SDKs, webhooks, or scoped service accounts. Account linking must be explicit; a Telegram, Discord, Slack, or other platform chat identifier is not canonical user identity.

---

## 20. Delivery plan

### Phase 0: architecture validation

- Define canonical schemas and threat model.
- Build representative personal, development, and travel datasets.
- Benchmark Mem0, Hindsight, Cognee, and native baseline.
- Benchmark Graphiti entity resolution and temporal updates.
- Validate Cloudflare-to-PostgreSQL latency through Hyperdrive.
- Prototype local E2EE envelopes and workspace-key rotation.
- Define the public provider contracts and configuration schema.
- Deliver a Docker Compose proof of concept using operator-provided credentials.
- Demonstrate swapping Mem0 and Graphiti without changing canonical records.

### Phase 1: secure personal memory

- Authentication, personal workspace, devices, and clients.
- Explicit identity/preferences/instructions.
- Event ledger, proposals, corrections, and deletion.
- Context compiler.
- MCP, REST, TypeScript SDK, and dashboard.
- Managed-private encryption.
- Open-source CLI with `init`, `doctor`, `migrate`, and generic MCP connection.
- PostgreSQL, SQLite, Mem0, Graphiti, S3-compatible, and local-filesystem provider adapters.
- Managed onboarding and non-technical memory dashboard.
- Memory approval inbox and plain-language permissions.
- Desktop/local installer prototype.

### Phase 2: development continuity

- Project/repository recognition.
- Agent work-trace capture.
- Git/file/test evidence.
- Questions and answers.
- Activity checkpoints and resume packages.
- Codex and Claude Code adapters.
- Connection marketplace entries for supported coding tools.

### Phase 3: travel continuity

- Trip entities and constraints.
- Search result evidence and shortlists.
- Freshness policies.
- Booking-state model.
- Protected traveller/vault references.

### Phase 4: shared workspaces

- Membership and roles.
- Entity-level permissions.
- Shared proposals and decisions.
- AI client administration.
- Key rotation and disclosure audit.
- Guided invitations, role explanations, and workspace recovery flows.

### Phase 5: strict E2EE

- Desktop/local gateway.
- SQLCipher local index.
- Device keys and recovery.
- MLS-based workspace membership.
- Encrypted synchronization.
- Local extraction, graph, and vector processing.

### Phase 6: enterprise

- Customer-owned deployment.
- SSO/SCIM.
- Regional controls.
- Customer-managed models and keys.
- Compliance, legal hold, and advanced audit.

---

## 21. Evaluation plan

The engine decision must be evidence-driven. Use identical datasets and measure:

- Preference precision and recall
- Contradiction handling
- Temporal correctness
- Project-handoff completeness
- Travel-constraint retention
- Entity-resolution accuracy
- Graph-path usefulness
- Source/provenance preservation
- Deletion completeness
- Cross-tenant leakage
- Prompt-injection persistence
- Write and retrieval latency
- Model and infrastructure cost
- Operational complexity
- Portability

Candidate configurations:

1. Mem0 OSS + Graphiti
2. Hindsight + Graphiti
3. Cognee
4. Native baseline + Graphiti

No vendor-reported benchmark should be accepted as the sole selection criterion.

---

## 22. Final decisions and open decisions

### Recommended decisions

- Build a user/workspace-centered platform rather than an agent-centered runtime.
- Use Cloudflare as the edge, coordination, workflow, vector, and artifact platform.
- Use PostgreSQL as canonical truth.
- Use Graphiti as the first temporal graph engine.
- Benchmark Mem0 OSS and Hindsight for semantic memory.
- Benchmark Cognee as an integrated alternative.
- Keep every third-party system behind a stable adapter.
- Provide managed-private mode first while designing strict E2EE formats from the beginning.
- Add shared workspaces only after personal isolation is tested thoroughly.
- Release the deployable core, CLI, contracts, and official provider adapters as open source.
- Treat Cloudflare as a reference deployment rather than a runtime requirement.
- Support BYO credentials and endpoints through validated provider packages.

### Decisions requiring product-owner review

1. Is strict E2EE required for the first public release, or can it follow managed-private mode?
2. Can recovery be impossible when a user loses every device/recovery key?
3. Should raw traces expire by default after consolidation?
4. Which memories may agents confirm automatically?
5. Should businesses be allowed to disable member-private memory within managed work devices?
6. Which AI providers are approved for managed extraction?
7. Are shared workspace memories readable by all members by default or entity-private by default?
8. Which two coding tools constitute the first handoff demonstration?
9. Should travel research remain read-only until action authorization is implemented?
10. Is the core protocol intended to become an independent open standard?
11. Which adapters receive official long-term support versus community support?
12. Should the hosted product support a hosted control plane with a customer-owned data plane?

---

## 23. Final recommendation

Build the platform around a canonical, secure continuity model and reuse specialized engines:

```text
Our platform owns:
identity + workspaces + keys + events + policies + provenance + context

Existing engines provide:
extraction + consolidation + embeddings + temporal graph + retrieval
```

The recommended first production stack is:

```text
Rust + Axum + Tokio + Tower
Official MCP Rust SDK
Optional thin Cloudflare Worker edge gateway
Durable Objects as optional hosted coordination
Queues + Workflows
R2
Vectorize
Hyperdrive
PostgreSQL + RLS + pgvector
Graphiti + Neo4j
Mem0 OSS or Hindsight after benchmark
Next.js dashboard
MCP + REST + TypeScript/Python SDKs
```

The same source distribution must also run using operator-selected providers:

```text
Own PostgreSQL or SQLite credentials
Own Mem0, Hindsight, or Cognee endpoint
Own Graphiti and graph-database credentials
Own vector and S3-compatible object stores
Own model and embedding credentials
Own OIDC provider
```

This approach avoids rebuilding mature memory and graph algorithms while preserving the parts that make the product defensible and trustworthy: portable identity, cross-agent continuity, workspace collaboration, provenance, tenant isolation, privacy, E2EE, open-source deployability, and infrastructure independence.
