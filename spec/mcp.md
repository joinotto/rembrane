# Rembrane MCP Surface

**Status:** Pre-alpha  
**Target:** MCP 2026-07-28 with compatibility for 2025-11-25 clients

Rembrane uses the official Rust MCP SDK and exposes tools over local stdio and remote Streamable HTTP. Both transports call the same application services as REST.

Official references:

- [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk)

## Connection identity

Workspace, subject, client identity, and grants come from the authenticated connection profile. They are not ordinary model-controlled tool arguments.

This prevents a model from changing `workspaceId` or `subjectId` in a tool call to probe another tenant.

Local stdio clients receive a narrowly scoped credential profile during `rembrane connect`. Remote clients use OAuth protected-resource discovery and purpose-appropriate grants.

The pre-alpha stdio implementation reads its connection profile from:

- `REMBRANE_DATABASE`
- `REMBRANE_PRINCIPAL_ID`
- `REMBRANE_WORKSPACE_ID`
- `REMBRANE_CLIENT_ID`
- `REMBRANE_WORKSPACE_KEY_ID`
- `REMBRANE_WORKSPACE_KEY_HEX` (development only)

Workspace and subject identifiers are intentionally absent from tool arguments.

## Tools

### `rembrane_create_trip`

Creates a new encrypted trip using the authenticated connection's `travel`
domain capability. The server assigns the opaque trip ID and canonical event
identity. Subsequent revisions and research capture require the exact returned
trip entity scope.

Arguments:

- `title`
- `origin`
- `destinations`
- `departNotBefore`
- `returnNotAfter`

The tool requires `trip:create` and `domain.travel`.

### `rembrane_capture_booking_research`

Captures one encrypted, time-bounded research observation under an exact trip
entity grant. Workspace, subject, client identity, record IDs, and canonical
event sequence are server-controlled. The tool requires
`booking-research:capture`.

Arguments:

- `tripId`
- `kind`: `flight`, `lodging`, `ground-transport`, `activity`, or `other`
- `provider`
- `summary`
- `sourceReference` (opaque; must not contain credentials)
- `evidenceSource`
- `observedAt` and `expiresAt` as canonical UTC timestamps

Annotations:

```json
{
  "readOnlyHint": false,
  "destructiveHint": false,
  "idempotentHint": false,
  "openWorldHint": false
}
```

### `rembrane_resolve_context`

Retrieves the minimum confirmed context authorized for the current client and purpose.

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["purpose", "query"],
  "properties": {
    "purpose": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255
    },
    "query": {
      "type": "string",
      "minLength": 1,
      "maxLength": 8192
    },
    "domain": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "entityId": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255
    },
    "activityId": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255
    },
    "maximumItems": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "default": 20
    },
    "maximumBytes": {
      "type": "integer",
      "minimum": 1,
      "maximum": 1048576,
      "default": 65536
    }
  }
}
```

Annotations:

```json
{
  "readOnlyHint": true,
  "destructiveHint": false,
  "idempotentHint": true,
  "openWorldHint": false
}
```

Although this tool does not mutate memory, it appends a disclosure receipt. That audit side effect must be documented and excluded from semantic idempotency decisions.

### `rembrane_propose_memory`

Submits an observation or candidate memory. It never creates confirmed memory.

Arguments:

- `scope`
- `kind`
- `content`
- `rationale`

The server assigns actor, client, evidence source, and workspace from the authenticated call. The tool requires `memory:propose`.

Annotations:

```json
{
  "readOnlyHint": false,
  "destructiveHint": false,
  "idempotentHint": false,
  "openWorldHint": false
}
```

### `rembrane_remember_preference`

Creates a confirmed preference for connection profiles explicitly granted
direct creation authority. An optional `domain`, `entityId`, or `activityId`
selects one exact scope; omitting all three creates a global preference.
Multiple scope selectors are invalid, and the selected scope must already
belong to the authenticated connection profile. General-purpose agent profiles
should use `rembrane_propose_memory` instead.

### `rembrane_resume_activity`

Retrieves the latest authorized checkpoint for an activity. It requires an
activity-scoped read grant. A successful result includes a unique
`disclosureId`; the server persists the exact checkpoint ID and version
disclosed before returning the response.

Arguments:

- `activityId`
- `currentStateFingerprint` (optional; when both current and recorded values
  exist, the response includes a `stale` comparison)

Annotations:

```json
{
  "readOnlyHint": true,
  "destructiveHint": false,
  "idempotentHint": true,
  "openWorldHint": false
}
```

### `rembrane_checkpoint_activity`

Creates or updates resumable state after meaningful work.

Arguments:

- `activityId`
- `entityId`
- `checkpointId`
- `expectedVersion`
- `goal`
- `summary`
- `nextSteps`
- `blockers`
- `stateFingerprint` (optional opaque digest of Git, filesystem, booking, or
  other external state)

The tool requires `activity:checkpoint`. Updates require the current expected version.

Annotations:

```json
{
  "readOnlyHint": false,
  "destructiveHint": false,
  "idempotentHint": false,
  "openWorldHint": false
}
```

### `rembrane_record_work_trace`

Records an agent observation under one authorized activity. Work traces enter
canonical storage as proposed observation memory and therefore cannot be
returned as confirmed user truth until a stronger confirmation workflow
approves them.

Arguments:

- `activityId`
- `entityId` (optional attribution)
- `summary`

The tool requires `memory:propose` plus exact activity scope authority.

### `rembrane_explain_context`

Explains the sources, scopes, versions, and disclosure policy associated with a context pack.

Arguments:

- `contextPackId`

The result must not reveal memories the current connection could not otherwise read.

### `rembrane_request_correction`

Proposes a correction to an existing memory. Agents receive proposal authority by default; direct revision requires a stronger grant.

Arguments:

- `memoryId`
- `expectedVersion`
- `replacement`
- `rationale`
- Optional one-of `domain`, `entityId`, or `activityId`; omission selects
  global scope.

### `rembrane_forget_memory`

Creates a deletion tombstone and begins provider deletion propagation.

Arguments:

- `memoryId`
- `expectedVersion`
- `reason`
- Optional one-of `domain`, `entityId`, or `activityId`; omission selects
  global scope.

Annotations:

```json
{
  "readOnlyHint": false,
  "destructiveHint": true,
  "idempotentHint": false,
  "openWorldHint": false
}
```

Clients should require explicit user confirmation before invoking this tool. The server still enforces `memory:delete`; client confirmation is not an authorization substitute.

## Resources

Resources are read-only views selected by the host application. Initial templates:

```text
rembrane://activities/{activityId}/checkpoint
rembrane://contexts/{contextPackId}/explanation
rembrane://connections/current/permissions
```

Private memory collections are not exposed as broadly enumerable resources.

## Prompts

Prompts are optional user-controlled helpers, not privileged system instructions:

- `continue_activity`
- `review_memory_proposals`
- `explain_remembered_context`

Retrieved memory content must remain typed, attributed context. It must not be promoted to system-level authority merely because it came from an MCP resource or prompt.

## Error behavior

- Malformed tool input returns a tool execution error that permits model correction.
- Missing authorization and unavailable records share a non-enumerating error.
- Version conflicts return the current safe metadata necessary to retry, but no newly unauthorized content.
- Provider failures do not silently fall back to weaker privacy or isolation behavior.

## Logging

The MCP server must not write plaintext memory, tool arguments containing memory, credentials, or context-pack contents to stdout, stderr, tracing fields, or protocol logs. For stdio transport, stdout is reserved exclusively for protocol messages.
