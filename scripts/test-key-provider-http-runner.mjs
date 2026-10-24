import assert from "node:assert/strict";
import http from "node:http";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const token = "key-provider-runner-secret";
const keyId = "mock-key-v1";
const sealed = new Map();
const workspaceGenerations = new Map();

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

function contextKey(context) {
  return JSON.stringify([
    context.workspaceId,
    context.recordId,
    context.recordVersion,
    context.purpose,
  ]);
}

const server = http.createServer(async (request, response) => {
  if (request.headers.authorization !== `Bearer ${token}`) {
    json(response, 401, { title: "unauthorized", status: 401 });
    return;
  }
  const url = new URL(request.url, "http://localhost");
  if (request.method === "GET" && url.pathname === "/v0.1/manifest") {
    json(response, 200, {
      providerId: "rembrane.mock-key-provider",
      protocolVersion: "0.1",
      algorithms: ["mock-aead"],
      maximumPlaintextBytes: 262144,
      supportsHistoricalKeys: true,
      supportsRotation: true,
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v0.1/seal") {
    const input = await readJson(request);
    if (Buffer.from(input.plaintextBase64, "base64").length > 262144) {
      json(response, 413, { title: "plaintext too large", status: 413 });
      return;
    }
    const ciphertextBase64 = randomBytes(32).toString("base64");
    const envelope = {
      ciphertextBase64,
      keyId,
      algorithm: "mock-aead",
      nonceBase64: randomBytes(24).toString("base64"),
    };
    sealed.set(ciphertextBase64, {
      context: contextKey(input.context),
      plaintextBase64: input.plaintextBase64,
    });
    json(response, 200, envelope);
    return;
  }
  if (request.method === "POST" && url.pathname === "/v0.1/open") {
    const input = await readJson(request);
    const record = sealed.get(input.envelope.ciphertextBase64);
    if (
      !record ||
      input.envelope.keyId !== keyId ||
      input.envelope.algorithm !== "mock-aead" ||
      record.context !== contextKey(input.context)
    ) {
      json(response, 422, { title: "invalid envelope", status: 422 });
      return;
    }
    json(response, 200, { plaintextBase64: record.plaintextBase64 });
    return;
  }
  if (request.method === "POST" && url.pathname === "/v0.1/rotate") {
    const input = await readJson(request);
    const previousGeneration = workspaceGenerations.get(input.workspaceId) ?? 0;
    if (
      !input.requestId ||
      !input.workspaceId ||
      !Number.isSafeInteger(input.generation) ||
      input.generation <= previousGeneration ||
      !Array.isArray(input.recipientIds) ||
      input.recipientIds.length === 0 ||
      new Set(input.recipientIds).size !== input.recipientIds.length
    ) {
      json(response, 409, { title: "invalid rotation", status: 409 });
      return;
    }
    workspaceGenerations.set(input.workspaceId, input.generation);
    json(response, 200, {
      providerId: "rembrane.mock-key-provider",
      requestId: input.requestId,
      workspaceId: input.workspaceId,
      generation: input.generation,
      keyId: `mock-key-v${input.generation}`,
      recipientIds: [...input.recipientIds].sort(),
    });
    return;
  }
  json(response, 404, { title: "not found", status: 404 });
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
assert.equal(typeof address, "object");
const script = fileURLToPath(
  new URL("./test-key-provider-http.sh", import.meta.url),
);
const child = spawn(script, ["mock-runner"], {
  env: {
    ...process.env,
    REMBRANE_KEY_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
    REMBRANE_KEY_PROVIDER_TOKEN: token,
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
assert.equal(stdout.includes(token), false);
assert.equal(stderr.includes(token), false);
console.log("key provider HTTP conformance runner checks passed");
