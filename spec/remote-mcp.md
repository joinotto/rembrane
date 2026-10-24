# Remote Streamable HTTP MCP

**Status:** Pre-alpha contract

The remote MCP endpoint uses the same tools and application services as local
stdio MCP. Transport selection never changes workspace authorization, scope
intersection, sensitive-data permissions, or disclosure auditing.

## Endpoints

- `POST /mcp` accepts authenticated JSON-RPC requests.
- `GET /mcp` may open the server-to-client event stream when negotiated by the
  MCP client.
- `DELETE /mcp` may terminate the session identified by `Mcp-Session-Id`.
- `GET /.well-known/oauth-protected-resource/mcp` returns RFC 9728 protected
  resource metadata for the canonical MCP resource URL.

Production remote endpoints must use HTTPS. Plaintext HTTP is allowed only on
an explicitly configured loopback listener or behind a trusted TLS-terminating
reverse proxy.

## Authentication

The endpoint accepts OAuth access tokens only through:

```text
Authorization: Bearer <access-token>
```

Tokens in query parameters, cookies, MCP tool arguments, or request bodies are
rejected. Missing or invalid credentials return `401` with a challenge shaped
like:

```text
WWW-Authenticate: Bearer resource_metadata="https://memory.example.test/.well-known/oauth-protected-resource/mcp"
```

An insufficient but otherwise valid grant returns `403`. Authentication errors
must not reveal whether a workspace, subject, memory, trip, or checkpoint
exists.

## Verified connection identity

Before an MCP request reaches a tool handler, the deployment's OAuth verifier
must validate at least:

- issuer and signature;
- exact MCP resource audience;
- expiry and not-before time;
- canonical subject and client identity;
- workspace membership or an equivalent workspace-bound grant;
- requested OAuth scopes.

Workspace, subject, and client identifiers are derived from verified claims.
They are never accepted from model-controlled tool parameters. OAuth scopes are
an outer ceiling: the existing Rembrane membership, entity scope, read
permission, and write permission checks still run for every operation.

## Session security

- Session identifiers are opaque capabilities but are never identity or
  authorization credentials.
- Every request is reauthenticated; possession of an `Mcp-Session-Id` alone is
  insufficient.
- Session state is bound to the verified issuer, subject, client, workspace,
  and token authorization ceiling.
- A session is rejected after token expiry, revocation, membership removal, or
  a material authorization change.
- Servers validate `Origin` on browser-capable requests and reject untrusted
  origins to reduce DNS-rebinding and cross-site request risks.
- Logs and errors never contain bearer tokens, authorization codes, refresh
  tokens, or raw verified claims.

## Initial OAuth scopes

- `rembrane:context:read`
- `rembrane:memory:write`
- `rembrane:checkpoint:read`
- `rembrane:checkpoint:write`
- `rembrane:travel:read`
- `rembrane:travel:write`

Each tool name maps to exactly one required outer scope. Unknown tool names
fail closed instead of inheriting a general MCP permission. Resume operations
use checkpoint-read authority; creating or updating a checkpoint requires
checkpoint-write authority.

Sensitive travel source references and profiles additionally require their
existing Rembrane connection permissions. Broad OAuth travel-read authority
does not silently grant either disclosure.
