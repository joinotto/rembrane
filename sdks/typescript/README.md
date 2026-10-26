# Rembrane TypeScript SDK

Zero-dependency ESM client for the authenticated Rembrane REST API.

> Rembrane is pre-alpha. Pin the package version and review protocol changes
> before upgrading.

## Requirements

- A Rembrane API endpoint over HTTPS, or an explicit loopback HTTP endpoint.
- A scoped bearer token. Do not embed tokens in browser bundles or source
  control.
- Node.js or another runtime with `fetch`, `URL`, `TextEncoder`, and ESM.

## Basic client

```js
import { RembraneClient } from "@rembrane/sdk";

const memory = new RembraneClient({
  baseUrl: process.env.REMBRANE_API_URL,
  token: process.env.REMBRANE_API_TOKEN,
});

const context = await memory.resolveContext({
  workspaceId: "workspace_personal",
  subjectId: "principal_hippo",
  purpose: "personalize-assistant",
  query: "How should I address the user?",
});
```

The client rejects redirects, non-loopback plaintext HTTP, malformed discovery,
oversized responses, and non-JSON API responses.

## Portable export

```js
const archive = await memory.exportPortableData({
  workspaceId: "workspace_personal",
  subjectId: "principal_hippo",
  format: "jsonl", // "markdown" or "graph-json"
});

await writeFile(archive.filename, archive.text, {
  encoding: "utf8",
  mode: 0o600,
  flag: "wx",
});
```

JSONL and Markdown exports are subject-scoped. Graph JSON exports cover the
workspace graph and therefore require an owner or admin. All three are
plaintext. Store them as sensitive files; use encrypted backup for recovery or
opaque transfer.

## Portable import

```js
const jsonl = await readFile("rembrane-memories.jsonl", "utf8");
const result = await memory.importPortableMemories({
  workspaceId: "workspace_personal",
  subjectId: "principal_hippo",
  expectedPreviousSequence: 42,
  jsonl,
});
```

The complete UTF-8 archive is bounded to 64 MiB before transport. The server
validates it atomically and imports records only as reviewable proposals.
`expectedPreviousSequence` prevents writing against stale workspace state.

## Test

```text
npm test
```
