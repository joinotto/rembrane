import assert from "node:assert/strict";
import { RembraneClient, RembraneError } from "./index.js";

const calls = [];
const client = new RembraneClient({
  baseUrl: "http://127.0.0.1:8787/v1",
  token: "test-token",
  fetch: async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      headers: { get: () => "application/json; charset=utf-8" },
      text: async () => '{"events":[]}',
    };
  },
});

await client.listAdministrativeAudit({
  workspaceId: "team",
  afterEpochSeconds: 10,
  limit: 20,
});
assert.equal(
  calls[0].url,
  "http://127.0.0.1:8787/v1/administrative-audit?workspaceId=team&afterEpochSeconds=10&limit=20",
);
assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
assert.equal(calls[0].init.redirect, "error");

assert.throws(
  () =>
    new RembraneClient({
      baseUrl: "http://memory.example.test/v1",
      token: "token",
      fetch: async () => {},
    }),
  /HTTPS or an explicit loopback URL/,
);

const failing = new RembraneClient({
  baseUrl: "https://memory.example.test/v1",
  token: "token",
  fetch: async () => ({
    ok: false,
    status: 403,
    headers: { get: () => "application/json" },
    text: async () => '{"code":"access_denied","message":"Access denied"}',
  }),
});
await assert.rejects(
  failing.rotateWorkspaceKey({ workspaceId: "team" }),
  (error) =>
    error instanceof RembraneError &&
    error.status === 403 &&
    error.code === "access_denied",
);
