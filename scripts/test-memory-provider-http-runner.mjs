import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const tokens = {
  primary: "memory-provider-primary-secret",
  other: "memory-provider-other-secret",
  readonly: "memory-provider-readonly-secret",
};
const connections = new Map([
  [
    `Bearer ${tokens.primary}`,
    {
      workspace: "workspace-primary",
      scopes: new Set([
        "memory:context:read",
        "memory:proposal:write",
        "memory:memory:delete",
        "memory:sync:read",
      ]),
    },
  ],
  [
    `Bearer ${tokens.other}`,
    {
      workspace: "workspace-other",
      scopes: new Set([
        "memory:context:read",
        "memory:proposal:write",
        "memory:memory:delete",
        "memory:sync:read",
      ]),
    },
  ],
  [
    `Bearer ${tokens.readonly}`,
    {
      workspace: "workspace-readonly",
      scopes: new Set(["memory:context:read"]),
    },
  ],
]);

const workspaces = new Map();
const idempotency = new Map();
let nextMemory = 1;
let discoveryRequests = 0;

function workspaceState(workspace) {
  let state = workspaces.get(workspace);
  if (!state) {
    state = { memories: new Map(), changes: [], sequence: 0 };
    workspaces.set(workspace, state);
  }
  return state;
}

function json(response, status, value, request) {
  const headers = { "content-type": "application/json" };
  if (request.headers["x-rembrane-request-id"]) {
    headers["x-rembrane-request-id"] =
      request.headers["x-rembrane-request-id"];
  }
  headers["x-rembrane-protocol-version"] = "0.1";
  response.writeHead(status, headers);
  response.end(JSON.stringify(value));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 300_000) {
        reject(new Error("request body exceeds mock limit"));
        request.destroy();
      }
    });
    request.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function authenticate(request, response, requiredScope) {
  const connection = connections.get(request.headers.authorization);
  if (!connection) {
    json(
      response,
      401,
      {
        code: "access_denied",
        ...(request.headers["x-rembrane-request-id"]?.includes("error-leak")
          ? { memoryContent: "must-not-leak" }
          : {}),
      },
      request,
    );
    return null;
  }
  if (!connection.scopes.has(requiredScope)) {
    json(response, 403, { code: "access_denied" }, request);
    return null;
  }
  return connection;
}

function appendChange(state, memory, operation) {
  state.sequence += 1;
  state.changes.push({
    changeId: `change_${state.sequence}`,
    sequence: state.sequence,
    resource: "memory",
    resourceId: memory.id,
    version: memory.version,
    operation,
    ...(operation === "upsert"
      ? {
          payload: memory.content,
          payloadSha256:
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
      : {}),
  });
}

const capabilities = [
  "resolve_context",
  "resolve_question",
  "record_event",
  "propose_memory",
  "checkpoint_activity",
  "record_disclosure",
  "delete_memory",
  "explain_memory",
  "sync_pull",
  "sync_push",
];
const operationScopes = {
  resolve_context: ["memory:context:read", "POST", "/v1/context/resolve"],
  resolve_question: [
    "memory:question:read",
    "POST",
    "/v1/questions/resolve",
  ],
  record_event: ["memory:event:write", "POST", "/v1/events"],
  propose_memory: [
    "memory:proposal:write",
    "POST",
    "/v1/memory/proposals",
  ],
  checkpoint_activity: [
    "memory:checkpoint:write",
    "POST",
    "/v1/activities/{activity_id}/checkpoint",
  ],
  record_disclosure: [
    "memory:disclosure:write",
    "POST",
    "/v1/disclosures/receipt",
  ],
  delete_memory: [
    "memory:memory:delete",
    "DELETE",
    "/v1/memories/{memory_id}",
  ],
  explain_memory: [
    "memory:memory:explain",
    "GET",
    "/v1/memories/{memory_id}/explain",
  ],
  sync_pull: ["memory:sync:read", "GET", "/v1/sync/pull"],
  sync_push: ["memory:sync:write", "POST", "/v1/sync/push"],
};
const operations = Object.entries(operationScopes).map(
  ([operation, [oauthScope, httpMethod, pathTemplate]]) => ({
    operation,
    capability: operation,
    oauthScope,
    httpMethod,
    pathTemplate,
  }),
);

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    if (
      request.method === "GET" &&
      url.pathname === "/.well-known/ai-memory"
    ) {
      discoveryRequests += 1;
      json(
        response,
        200,
        {
          providerId: "rembrane.mock-memory-provider",
          providerVersion: "test",
          protocolVersion: "0.1",
          transports: ["https"],
          capabilities,
          privacyMode: "end_to_end_encrypted",
          supportedDomains: ["personal", "development", "travel"],
          limits: {
            maximumContextItems: 100,
            maximumContextBytes: 1_048_576,
            maximumEventBatchItems: 100,
            maximumSyncBatchItems: 100,
          },
          operations,
          ...(discoveryRequests <= 2 ? { unexpected: true } : {}),
        },
        request,
      );
      return;
    }

    if (
      request.method === "POST" &&
      url.pathname === "/v1/memory/proposals"
    ) {
      const connection = authenticate(
        request,
        response,
        "memory:proposal:write",
      );
      if (!connection) return;
      const input = await readJson(request);
      const replayKey = `${connection.workspace}\0${input.idempotencyKey}`;
      const replay = idempotency.get(replayKey);
      if (replay) {
        json(response, 200, replay, request);
        return;
      }
      const state = workspaceState(connection.workspace);
      const memory = {
        id: `memory_${nextMemory++}`,
        version: 1,
        content: input.content,
        kind: input.kind,
        selector: input.selector,
      };
      state.memories.set(memory.id, memory);
      appendChange(state, memory, "upsert");
      const result = { memoryId: memory.id, version: memory.version };
      idempotency.set(replayKey, result);
      json(response, 200, result, request);
      return;
    }

    if (
      request.method === "POST" &&
      url.pathname === "/v1/context/resolve"
    ) {
      const connection = authenticate(
        request,
        response,
        "memory:context:read",
      );
      if (!connection) return;
      const input = await readJson(request);
      const state = workspaceState(connection.workspace);
      const items = [...state.memories.values()]
        .filter(
          (memory) =>
            !memory.deleted &&
            (memory.content.includes(input.query) ||
              input.query.includes(memory.content)),
        )
        .slice(0, input.maximumItems)
        .map((memory) => ({
          memoryId: memory.id,
          version: memory.version,
          scope: memory.selector,
          kind: memory.kind,
          content: memory.content,
          evidence: [
            {
              evidenceId: `evidence_${memory.id}`,
              source: "imported_record",
            },
          ],
          confidenceMillionths: 1_000_000,
          validFromEpochSeconds: 1,
          validUntilEpochSeconds: null,
          sensitivity: "personal",
          disclosureConstraints: [{ type: "purpose_bound" }],
        }));
      json(
        response,
        200,
        {
          contextPackId: `context_pack_${connection.workspace}`,
          disclosureId: `disclosure_${connection.workspace}_${state.sequence}`,
          items,
        },
        request,
      );
      return;
    }

    const deletion = url.pathname.match(/^\/v1\/memories\/([^/]+)$/);
    if (request.method === "DELETE" && deletion) {
      const connection = authenticate(
        request,
        response,
        "memory:memory:delete",
      );
      if (!connection) return;
      const input = await readJson(request);
      const pathMemoryId = decodeURIComponent(deletion[1]);
      if (pathMemoryId !== input.memoryId) {
        json(response, 400, { code: "invalid_request" }, request);
        return;
      }
      const state = workspaceState(connection.workspace);
      const memory = state.memories.get(pathMemoryId);
      if (
        !memory ||
        memory.deleted ||
        memory.version !== input.expectedVersion
      ) {
        json(response, 409, { code: "conflict" }, request);
        return;
      }
      const deletedVersion = memory.version;
      memory.version += 1;
      memory.deleted = true;
      appendChange(state, memory, "delete");
      json(
        response,
        200,
        {
          memoryId: memory.id,
          deletedVersion,
          tombstoneVersion: memory.version,
        },
        request,
      );
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/sync/pull") {
      const connection = authenticate(request, response, "memory:sync:read");
      if (!connection) return;
      const state = workspaceState(connection.workspace);
      const maximumItems = Number(url.searchParams.get("maximumItems"));
      const changes = state.changes.slice(0, maximumItems);
      json(
        response,
        200,
        {
          changes,
          nextCursor: `cursor_${connection.workspace}_${state.sequence
            .toString()
            .padStart(8, "0")}`,
          hasMore: state.changes.length > changes.length,
        },
        request,
      );
      return;
    }

    json(response, 404, { code: "not_found" }, request);
  } catch {
    if (!response.headersSent) {
      json(response, 400, { code: "invalid_request" }, request);
    } else {
      response.destroy();
    }
  }
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert.equal(typeof address, "object");
const script = fileURLToPath(
  new URL("./run-memory-provider-conformance.mjs", import.meta.url),
);
const secretDirectory = await mkdtemp(
  join(tmpdir(), "rembrane-memory-provider-runner-"),
);
const tokenFiles = Object.fromEntries(
  await Promise.all(
    Object.entries(tokens).map(async ([role, token]) => {
      const path = join(secretDirectory, role);
      await writeFile(path, `${token}\n`, { mode: 0o600 });
      return [role, path];
    }),
  ),
);
const invalidDiscoveryChild = spawn(
  process.execPath,
  [script, "invalid-discovery"],
  {
    env: {
      ...process.env,
      REMBRANE_MEMORY_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
      REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN_REFERENCE:
        "file:/does-not-exist/primary",
      REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN_REFERENCE:
        "file:/does-not-exist/other",
      REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN_REFERENCE:
        "file:/does-not-exist/readonly",
    },
    stdio: ["ignore", "pipe", "pipe"],
  },
);
let invalidDiscoveryStderr = "";
invalidDiscoveryChild.stderr.setEncoding("utf8").on("data", (chunk) => {
  invalidDiscoveryStderr += chunk;
});
const invalidDiscoveryStatus = await new Promise((resolve) =>
  invalidDiscoveryChild.on("close", resolve),
);
assert.notEqual(invalidDiscoveryStatus, 0);
assert.match(invalidDiscoveryStderr, /provider discovery is not conformance-compatible/);
assert.doesNotMatch(invalidDiscoveryStderr, /does-not-exist|secret reference/);

const shellScript = fileURLToPath(
  new URL("./test-memory-provider-http.sh", import.meta.url),
);
const invalidShellDiscoveryChild = spawn(
  "sh",
  [shellScript, "invalid-shell-discovery"],
  {
    env: {
      ...process.env,
      REMBRANE_MEMORY_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
      REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN: "",
      REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN: "",
      REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  },
);
let invalidShellDiscoveryStderr = "";
invalidShellDiscoveryChild.stderr.setEncoding("utf8").on("data", (chunk) => {
  invalidShellDiscoveryStderr += chunk;
});
const invalidShellDiscoveryStatus = await new Promise((resolve) =>
  invalidShellDiscoveryChild.on("close", resolve),
);
assert.notEqual(invalidShellDiscoveryStatus, 0);
assert.doesNotMatch(
  invalidShellDiscoveryStderr,
  /bearer tokens must be non-empty|tokens must represent distinct connections/,
);

const child = spawn(process.execPath, [script, "mock-runner"], {
  env: {
    ...process.env,
    REMBRANE_MEMORY_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
    REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN_REFERENCE: `file:${tokenFiles.primary}`,
    REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN_REFERENCE: `file:${tokenFiles.other}`,
    REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN_REFERENCE: `file:${tokenFiles.readonly}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let stdout = "";
let stderr = "";
child.stdout.setEncoding("utf8").on("data", (chunk) => {
  stdout += chunk;
});
child.stderr.setEncoding("utf8").on("data", (chunk) => {
  stderr += chunk;
});
const status = await new Promise((resolve) => child.on("close", resolve));
assert.equal(status, 0, stderr);

const leakingErrorChild = spawn(process.execPath, [script, "error-leak"], {
  env: {
    ...process.env,
    REMBRANE_MEMORY_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
    REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN_REFERENCE: `file:${tokenFiles.primary}`,
    REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN_REFERENCE: `file:${tokenFiles.other}`,
    REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN_REFERENCE: `file:${tokenFiles.readonly}`,
  },
  stdio: ["ignore", "pipe", "pipe"],
});
let leakingErrorStderr = "";
leakingErrorChild.stderr.setEncoding("utf8").on("data", (chunk) => {
  leakingErrorStderr += chunk;
});
const leakingErrorStatus = await new Promise((resolve) =>
  leakingErrorChild.on("close", resolve),
);
assert.notEqual(leakingErrorStatus, 0);
assert.match(leakingErrorStderr, /invalid closed error response/);

await new Promise((resolve, reject) =>
  server.close((error) => (error ? reject(error) : resolve())),
);
await rm(secretDirectory, { recursive: true });

const result = JSON.parse(stdout);
assert.equal(result.profileId, "rembrane.memory-provider.core");
assert.equal(result.fixtureId, "rembrane.memory-provider.core.lifecycle");
assert.equal(
  result.profileSha256,
  createHash("sha256")
    .update(
      await readFile(
        new URL("../spec/conformance/memory-provider-core.json", import.meta.url),
      ),
    )
    .digest("hex"),
);
assert.equal(
  result.fixtureSha256,
  createHash("sha256")
    .update(
      await readFile(
        new URL(
          "../spec/conformance/memory-provider-core-fixtures.json",
          import.meta.url,
        ),
      ),
    )
    .digest("hex"),
);
assert.equal(result.result, "pass");
assert.equal(result.provider.id, "rembrane.mock-memory-provider");
assert.equal(result.cases.length, 11);
assert.equal(result.cases.every((testCase) => testCase.result === "pass"), true);
for (const token of Object.values(tokens)) {
  assert.equal(stdout.includes(token), false);
  assert.equal(stderr.includes(token), false);
}
for (const state of workspaces.values()) {
  assert.equal(
    [...state.memories.values()].some((memory) => !memory.deleted),
    false,
    "conformance runner must clean up every active fixture",
  );
}
console.log("memory provider HTTP conformance runner checks passed");
