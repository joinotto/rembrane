# Bot and Platform Integration Architecture

## 1. Decision

The central memory framework can work with AI tools, agents, applications, and messaging bots, but “universal integration” has several levels.

A cooperative bot can use the memory layer natively through MCP, REST, an SDK, or an OAuth-connected tool. A closed bot that is only available as an iMessage or WhatsApp contact cannot be transparently modified or have private memory injected into its conversation unless its operator provides an integration surface.

The product must therefore support:

1. Native memory-provider integration.
2. MCP, tool, skill, and plugin integration.
3. A user-controlled messaging gateway for bots operated by the user or workspace.
4. Explicit share extensions and context cards for closed applications.
5. Export and copy/paste fallback for otherwise unsupported tools.

Compatibility must be described honestly with a verified compatibility tier, not a generic “works everywhere” badge.

## 2. Separate the channel, agent, and memory

Messaging transport, agent runtime, and memory are independent layers:

```text
User
  │
  ▼
Channel adapter
WhatsApp / iMessage / web / CLI / IDE
  │
  ▼
Agent adapter
Muse / Tab / Grok / custom bot / coding agent
  │
  ▼
Central memory client
identity link → authorization → context resolve → event/proposal write
  │
  ▼
Canonical memory platform
events + memories + activities + graph + policies + audit
```

This prevents channel identifiers, such as a phone number, from becoming the canonical user identity and lets one agent operate on several channels without duplicating memory.

## 3. Compatibility tiers

| Tier | Integration | Experience | Requirement |
|---|---|---|---|
| 1 | Native provider | Automatic read, handoff, and proposed writes | Bot vendor integrates the protocol or SDK |
| 2 | MCP/tool/plugin | Nearly native, subject to host capabilities | Host supports external tools, MCP, skills, or plugins |
| 3 | User-controlled gateway | Automatic for conversations routed through the gateway | User or workspace controls the bot endpoint/channel |
| 4 | Share extension/context card | User explicitly inserts or captures context | OS/application exposes a sharing or extension surface |
| 5 | Import/export | Manual or scheduled continuity | Tool provides exports or accepts instructions/files |
| 0 | Unsupported closed conversation | No invisible integration | No API, tool, extension, export, or vendor cooperation |

The dashboard and CLI should display the tier, permissions, last successful synchronization, and limitations for every connection.

## 4. Native bot flow

The ideal bot invokes the memory layer before and after each meaningful turn:

```text
Incoming message
  → identify linked central-memory principal
  → classify workspace, domain, entity, and activity
  → request the minimum authorized context pack
  → merge it with current conversation and bot-local state
  → run the agent
  → return the response
  → append evidence events
  → submit memory proposals and an activity checkpoint
```

Before asking the user a repeated question, the bot should call `questions.resolve`. It should ask only when the answer is absent, ambiguous, stale, conflicting, or unauthorized for that bot.

Example:

```ts
const context = await memory.resolve({
  principal: linkedUser,
  agent: "travel-bot",
  channel: "whatsapp",
  message,
  purpose: "continue_trip_planning"
});

const result = await bot.run({
  message,
  context: context.items
});

await memory.record({
  events: result.evidenceEvents,
  proposals: result.memoryProposals,
  checkpoint: result.activityCheckpoint
});
```

The bot should never download a user's complete memory archive for an ordinary turn.

## 5. Central memory and a bot's own memory

The two systems should coexist rather than force every bot to delete its internal memory.

### 5.1 Central memory owns

- User-confirmed identity and preferences.
- Portable instructions, such as “Call me Hippo.”
- Workspace facts, permissions, and shared decisions.
- Project, trip, and activity continuity.
- Cross-tool provenance, corrections, supersession, and deletion.
- Disclosure receipts showing which client received which memory.

### 5.2 Bot-local memory owns

- Temporary reasoning and execution state.
- Provider-specific caches.
- Tool results needed only during the current run.
- Agent implementation details that are not portable user memory.
- Short-lived conversation optimization.

### 5.3 Merge precedence

```text
current explicit user instruction
  > entity/activity-scoped confirmed central memory
  > global confirmed central memory
  > shared workspace memory authorized for this purpose
  > recent bot observation
  > model or agent default
```

A bot observation that conflicts with confirmed central memory must not silently overwrite it. The bot submits a proposed correction with evidence. The platform then applies its confirmation and conflict policy.

Bot caches should retain canonical memory IDs, version numbers, and expiry times. This avoids creating mirrored, diverging copies.

## 6. Memory Provider Protocol

The open-source project should define an implementation-independent protocol usable without adopting the complete server.

### 6.1 Discovery and capability negotiation

Proposed discovery document:

```text
GET /.well-known/ai-memory
```

It advertises:

- Protocol and schema versions.
- OAuth endpoints.
- Supported transports.
- Read, proposal, checkpoint, deletion, and disclosure capabilities.
- E2EE mode and whether context is compiled locally or remotely.
- Maximum context-pack sizes.
- Supported domains and provider extensions.

### 6.2 Core operations

```text
POST /v1/context/resolve
POST /v1/questions/resolve
POST /v1/events
POST /v1/memory/proposals
POST /v1/activities/{activity_id}/checkpoint
POST /v1/disclosures/receipt
POST /v1/sync/pull
POST /v1/sync/push
```

Equivalent MCP tools should call the same application services:

```text
memory_resolve_context
memory_find_answer
memory_propose
memory_record_event
memory_checkpoint_activity
memory_explain
memory_forget
```

Each context pack should include source IDs, provenance, scope, confidence, validity interval, version, sensitivity label, and disclosure constraints.

### 6.3 Connection and scopes

Use OAuth authorization-code flow with PKCE for end-user account linking. Self-hosted and local tools may also use device authorization, mutually authenticated local connections, or narrowly scoped service credentials.

Example grants:

```text
profile.basic:read
preferences.assistant:read
domain.travel:read
entity.trip_123:read
activity.trip_123:checkpoint
memory:propose
events:append
```

There should be no universal `all-memory:read` default.

## 7. WhatsApp

### 7.1 Bots operated by the user, workspace, or integrating vendor

For a bot connected through the WhatsApp Business Platform:

```text
WhatsApp webhook
  → verify event
  → map business number + sender to an explicitly linked principal
  → resolve minimal central context
  → run bot/model
  → append events and proposals
  → send reply through the WhatsApp API
```

Meta's published WhatsApp Business Platform uses business phone numbers, APIs, and webhooks for business messaging. Embedded Signup can be used to onboard organizations that bring their own WhatsApp business assets.

Official references:

- [WhatsApp Business Platform](https://www.postman.com/meta/whatsapp-business-platform/overview)
- [WhatsApp Cloud API collection](https://www.postman.com/meta/whatsapp-business-platform/collection/wlk6lh4/whatsapp-cloud-api)
- [Receiving message webhooks](https://whatsapp.github.io/WhatsApp-Nodejs-SDK/receivingMessages/)
- [Embedded Signup](https://www.postman.com/meta/whatsapp-business-platform/documentation/du6gzjv/embedded-signup)

### 7.2 Existing closed bot contacts

The Business Platform does not give this framework arbitrary access to a consumer's direct conversation with another company's bot. Therefore, a conversation between the user and an existing closed bot cannot be silently intercepted.

One of these must happen:

1. The bot company integrates the central memory protocol.
2. The bot exposes a compatible tool, MCP, OAuth, API, or plugin.
3. The user talks to a gateway bot operated by this framework, which then calls a selected model or agent.
4. The user explicitly shares a message or generated context card.
5. The user imports an available conversation export.

Routing through the central gateway produces a new user-controlled bot experience; it does not retrofit memory into the vendor's original WhatsApp contact.

### 7.3 Reference self-hosted gateway

Rembrane ships an opt-in, narrowly scoped webhook process. It receives the
canonical SQLite path, three deployment-owned WhatsApp secrets, and a
record-cipher capability used to seal the durable inbox. It receives no
Rembrane API bearer token, default principal, read grants, or memory-service
authorization. Prefer a customer-controlled HTTP key provider so raw workspace
keys do not enter the gateway process.

```sh
export REMBRANE_WHATSAPP_APP_SECRET='<Meta app secret>'
export REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET='<stable random secret>'
export REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN='<random verification token>'

docker compose -f compose.yaml -f compose.whatsapp.yaml up -d \
  rembrane rembrane-whatsapp-gateway rembrane-channel-worker
```

Configure the HTTPS proxy or tunnel to forward the exact public webhook path
to `http://rembrane-whatsapp-gateway:8790/webhooks/whatsapp`. Port 8790 binds
to host loopback by default. The gateway authenticates the raw POST body,
rejects stale events, maps keyed pseudonymous sender identifiers through an
active canonical membership, and atomically reserves replay protection.

The three secrets must be distinct, at least 32 bytes each, and supplied by a
deployment secret manager. Never store them in canonical memory, sender
bindings, committed Compose files, or URLs.

The gateway defaults to the value variables shown above. A self-hosted
deployment can instead point each credential at an environment variable or a
protected regular file:

```sh
export REMBRANE_WHATSAPP_APP_SECRET_REFERENCE='file:/run/secrets/meta-app'
export REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET_REFERENCE='file:/run/secrets/whatsapp-lookup'
export REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN_REFERENCE='env:META_VERIFY_TOKEN'
```

Reference values are metadata, not credentials. Supported locator syntax is
`env:VARIABLE`, `file:/absolute/or/deployment/path`, and
`external:provider:key`. The shipped local resolver supports `env:` and
protected `file:` references and fails closed for `external:`. Deployments
using Keychain, Vault, or a cloud secret manager can supply a resolver for the
external provider. Resolved strings are zeroized and only derived HMAC keys
are retained.

When using file references in Compose, add a deployment-owned read-only volume
mount that exposes the referenced files inside the gateway container. Each
file must be a regular, non-symlink file readable by the container process and
must not grant group or other permission bits. Do not commit the source
directory or file contents.

The gateway acknowledges a new message only after active sender resolution,
replay reservation, and authenticated encryption into the tenant inbox commit
in one SQLite transaction. Configure the same `REMBRANE_KEY_PROVIDER` profile
used by trusted Rembrane workers. Environment key material remains a local
pre-alpha development option, not a production deployment recommendation.

Set `REMBRANE_CHANNEL_PROCESSOR_URL` to the HTTPS origin of a cooperative bot
or agent service and keep `REMBRANE_CHANNEL_PROCESSOR_TOKEN` in the deployment
secret manager. The worker posts to `/v1/channel/messages`; the canonical
channel and event ID form the downstream idempotency key. A processor must
return success only after its own durable or idempotent handling succeeds.
Failed calls remain pending in the encrypted inbox.

### 7.4 Explicit mobile and iMessage shares

Rembrane can accept text that a user explicitly selects in an iOS share
extension or companion app. It does not read the Messages database, intercept
iMessage traffic, or gain background access to conversations. The companion
signs the exact JSON bytes with its deployment-provisioned secret and sends
them to `POST /v1/shares` with `X-Rembrane-Signature-256:
sha256=<lowercase-hex-hmac>`.

```json
{
  "account_id": "opaque-account-id",
  "device_id": "opaque-device-id",
  "event_id": "unique-share-id",
  "text": "user-selected text",
  "shared_at_epoch_seconds": 1792867200
}
```

Enroll the device using environment-only raw identifiers, then start the
loopback-published gateway behind a deployment-owned HTTPS proxy:

```sh
export REMBRANE_MOBILE_SHARE_ACCOUNT_ID='<opaque account id>'
export REMBRANE_MOBILE_SHARE_DEVICE_ID='<opaque device id>'
export REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET='<stable random secret>'
rembrane channel bind-mobile-share --database ./rembrane.db \
  --principal owner_01 --workspace workspace_01 --subject owner_01 \
  --client ios_share_01 --request request_01

export REMBRANE_MOBILE_SHARE_SIGNING_SECRET='<distinct random secret>'
docker compose -f compose.yaml -f compose.mobile-share.yaml up -d \
  rembrane rembrane-mobile-share-gateway
```

The signing and lookup secrets must be distinct and at least 32 bytes. The
gateway has no memory-read token or default identity. It maps the authenticated
account/device pseudonyms through an active membership and acknowledges only
after replay reservation and encrypted durable admission commit atomically.
The Swift package includes `CryptoKitMobileShareSigner`; load its secret from
an app-group-accessible Keychain item shared with the extension, never from
source code, `UserDefaults`, the shared envelope, or canonical memory.

An owner or administrator can bind an active member without placing raw phone
identifiers in process arguments:

```sh
export REMBRANE_WHATSAPP_ACCOUNT_ID='<business phone-number ID>'
export REMBRANE_WHATSAPP_SENDER_ID='<member WhatsApp sender ID>'
export REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET='<same stable gateway secret>'

rembrane channel bind-whatsapp \
  --database "$REMBRANE_DATABASE" \
  --principal principal_admin \
  --workspace workspace_team \
  --subject principal_member \
  --client client_whatsapp \
  --request request_whatsapp_bind_01
```

The command emits canonical IDs and status only. Shell history, logs, and the
database never receive the raw identifiers as command-line arguments or
stored binding values. Use `unbind-whatsapp` with the same identity arguments
and a new request ID to revoke the binding. Creation and revocation commit
content-free administrative audit evidence in the same database transaction
as the binding mutation.

## 8. iMessage

Apple's published Messages framework is centered on app extensions and interactive content inside Messages. It is not documented as a general server-side webhook API for arbitrary iMessage conversations. This means the supported integration should be explicit and user-controlled.

Official reference: [Apple Messages framework](https://developer.apple.com/documentation/messages).

Recommended integration:

- An iOS/iMessage extension that lets the user select “Add to memory,” “Retrieve context,” or “Continue activity.”
- A compact context card that the user can inspect before inserting it into a conversation.
- A local companion app that performs identity, decryption, retrieval, and context compilation on the authorized device.
- No automatic capture of every conversation.

The repository includes `examples/ios-imessage-extension`, a compile-checked
`MSMessagesAppViewController` reference. Because the public Messages API does
not expose transcript or composer contents, the user explicitly pastes or
types the text, reviews a clear confirmation prompt, and submits only that
text through the same signed mobile-share gateway.

A macOS helper that reads or automates local Messages data would depend on private, brittle, permission-sensitive surfaces. If an experimental adapter is offered, it must be optional, local-only, allowlist exact threads, default to read-only capture, require explicit send confirmation, and never be the project's primary integration path.

## 9. Named consumer bots

Tab describes an assistant used through Messages, while Meta describes Muse as available in its app and directly through WhatsApp. These products illustrate why the integration must be negotiated at the agent layer, not assumed from the messaging channel.

- [Tab product site](https://tab.bot/)
- [Tab terms describing its iMessage contact model](https://addtab.app/terms)
- [Meta Muse](https://ai.meta.com/muse/)
- [Meta announcement for Muse](https://about.fb.com/news/2026/09/introducing-muse-personal-ai-agent/)
- [xAI Grok Bot documentation](https://docs.x.ai/grok-bot/overview)

For Tab, Muse, Grok, Instinct, or any similar closed service, support should be marked “native” only after its operator implements or exposes a verified integration. Being reachable through iMessage or WhatsApp alone is not sufficient.

The framework should publish a small vendor integration kit and invite these companies to connect:

- OpenAPI specification.
- MCP server and client examples.
- TypeScript, Python, Rust, Swift, and Kotlin clients.
- OAuth account-linking reference UI.
- Context-pack and memory-proposal schemas.
- Integration conformance suite.
- Security and privacy checklist.

## 10. Identity and channel linking

A phone number or Apple messaging identifier must not automatically become the memory account.

Safe linking flow:

1. User initiates “Connect central memory” in the bot.
2. Bot opens OAuth or displays a short-lived one-time link/code.
3. User selects the workspace and permitted domains/entities.
4. Central memory creates a pseudonymous connection principal for that bot.
5. Channel identifiers are encrypted and stored only as connection aliases.
6. The user can revoke the bot without changing or deleting the canonical account.

Account linking must defend against recycled phone numbers, forwarded codes, SIM swaps, compromised devices, and mistaken workspace selection.

## 11. Group-chat rules

Group messages create a different authorization context from direct messages:

- Treat each group as a separate conversation scope, not as the user's private context.
- Never inject private personal memory merely because one member authorized the bot.
- Read only memories explicitly shared with that group or its linked workspace/activity.
- Record who supplied each statement and who is allowed to see it.
- Do not promote statements about another participant into durable memory as fact without policy and consent.
- Avoid exposing membership, travel, health, financial, or workplace information to new group members.
- Re-evaluate access whenever participants change.

## 12. Minimal disclosure and E2EE

End-to-end encryption of a messaging channel protects messages on that channel; it does not automatically authorize this separate memory system to read them.

In strict-E2EE deployments:

- The authorized device or customer-controlled gateway decrypts memory and compiles the context pack.
- Only the minimum task-relevant context is disclosed to the bot.
- Every disclosed item receives a receipt containing client, purpose, memory IDs, versions, and time.
- Sensitive scopes can require confirmation for every disclosure.
- The server stores ciphertext and encrypted indexes or routing metadata permitted by the selected privacy mode.

Users must be warned that context sent to an external bot is then subject to that bot provider's data practices, regardless of how securely the central copy was stored.

## 13. CLI and configuration

```text
rembrane connect mcp
rembrane connect bot --manifest ./bot.json
rembrane connect whatsapp --business-account <id>
rembrane connect imessage-extension
rembrane connections list
rembrane connections inspect <connection>
rembrane connections permissions <connection>
rembrane connections revoke <connection>
rembrane bridge start --channel whatsapp --agent <adapter>
rembrane context-card create --entity <entity>
rembrane provider test
```

Example bot manifest:

```yaml
id: example.travel.bot
name: Example Travel Bot
protocol_version: 1
transports: [rest, mcp]
requested_scopes:
  - profile.basic:read
  - domain.travel:read
  - memory:propose
capabilities:
  context_resolution: true
  question_resolution: true
  activity_checkpoint: true
  deletion_propagation: true
data_location: vendor_cloud
```

## 14. Product requirements

1. Maintain a public compatibility registry with tested versions and tiers.
2. Build protocol conformance tests before building many one-off adapters.
3. Make the gateway an optional adapter, not the canonical memory implementation.
4. Require explicit account linking and least-privilege grants.
5. Label central and bot-local context separately.
6. Preserve stable IDs and versions across caches.
7. Support revocation, deletion propagation, and stale-cache invalidation.
8. Log disclosures without logging plaintext memory.
9. Never claim invisible integration with a closed messaging contact.
10. Offer a useful manual context-card fallback where automation is unavailable.

## 15. Recommended delivery order

### Phase 1

- Protocol schemas and discovery document.
- OAuth account linking and scoped client grants.
- MCP, REST, TypeScript, Python, and Rust clients.
- Reference bot adapter and conformance suite.
- Context compiler, disclosure receipts, and proposed-write workflow.

### Phase 2

- User-controlled WhatsApp Business gateway.
- Web chat and generic webhook adapters.
- Context-card generator and mobile share flow.
- Public compatibility registry.

### Phase 3

- iOS companion and iMessage extension.
- Swift and Kotlin SDKs.
- Vendor partnership integrations.
- Workspace onboarding through WhatsApp Embedded Signup.

### Phase 4

- Carefully sandboxed experimental local adapters.
- Import/export connectors for closed platforms.
- Federated memory-provider discovery and cross-provider synchronization.

## 16. Final architectural principle

The framework should not attempt to scrape every assistant. It should become the neutral memory-provider standard that assistants choose to connect to, while supplying gateways and explicit user-mediated fallbacks where platforms are closed.

The durable advantage is not a collection of fragile bot-specific hacks. It is a secure canonical memory model, a tiny integration protocol, strong identity and permission controls, and enough adapters that adopting the standard is easier than building another isolated memory silo.
