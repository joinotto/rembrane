import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const token = "provider-runner-secret";
const projections = new Map();

function json(response, status, value) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
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

const server = http.createServer(async (request, response) => {
  if (request.headers.authorization !== `Bearer ${token}`) {
    json(response, 401, { type: "about:blank", title: "unauthorized", status: 401 });
    return;
  }

  const url = new URL(request.url, "http://localhost");
  if (request.method === "GET" && url.pathname === "/v0.1/manifest") {
    json(response, 200, {
      id: "test.sidecar",
      version: "test",
      protocolVersion: "0.1",
      capabilities: [
        "index",
        "search",
        "delete",
        "workspace-filter",
        "versioned-records",
      ],
      plaintextProcessing: true,
      limits: {
        maximumBatchItems: 1,
        maximumContentBytes: 262144,
        maximumCandidates: 100,
      },
    });
    return;
  }

  if (request.method === "PUT" && url.pathname === "/v0.1/projections") {
    const projection = await readJson(request);
    const key = `${projection.workspaceId}\u0000${projection.memoryId}`;
    const current = projections.get(key);
    if (current && current.version > projection.version) {
      json(response, 409, { type: "about:blank", title: "newer version", status: 409 });
      return;
    }
    projections.set(key, projection);
    response.writeHead(204).end();
    return;
  }

  if (request.method === "POST" && url.pathname === "/v0.1/search") {
    const query = await readJson(request);
    const candidates = [...projections.values()]
      .filter(
        (projection) =>
          projection.workspaceId === query.workspaceId &&
          projection.content === query.query,
      )
      .slice(0, query.maximumCandidates)
      .map((projection) => ({
        memoryId: projection.memoryId,
        version: projection.version,
        scoreMillionths: 1000000,
      }));
    json(response, 200, { candidates });
    return;
  }

  const deletion = url.pathname.match(
    /^\/v0\.1\/projections\/([^/]+)\/([^/]+)$/,
  );
  if (request.method === "DELETE" && deletion) {
    const workspaceId = decodeURIComponent(deletion[1]);
    const memoryId = decodeURIComponent(deletion[2]);
    const key = `${workspaceId}\u0000${memoryId}`;
    const current = projections.get(key);
    const throughVersion = Number(url.searchParams.get("throughVersion"));
    if (current && current.version <= throughVersion) {
      projections.delete(key);
    }
    response.writeHead(204).end();
    return;
  }

  json(response, 404, { type: "about:blank", title: "not found", status: 404 });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert.equal(typeof address, "object");
const script = fileURLToPath(new URL("./test-provider-http.sh", import.meta.url));

const child = spawn(script, ["mock-runner"], {
  env: {
    ...process.env,
    REMBRANE_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
    REMBRANE_PROVIDER_TOKEN: token,
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
await new Promise((resolve, reject) =>
  server.close((error) => (error ? reject(error) : resolve())),
);

assert.equal(status, 0, stderr);
assert.equal(JSON.parse(stdout).result, "pass");
assert.equal(projections.size, 0, "runner must clean up its fixture");
assert.equal(stdout.includes(token), false);
assert.equal(stderr.includes(token), false);
console.log("provider HTTP conformance runner checks passed");
