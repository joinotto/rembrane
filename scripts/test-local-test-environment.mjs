import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

const helper = fileURLToPath(new URL("./local-test-environment.sh", import.meta.url));
const sentinel = "fixture-secret-must-not-be-printed";
const polluted = {
  ...process.env,
  REMBRANE_BIN: "/fixture/rembrane",
  REMBRANE_API_BIN: "/fixture/api",
  REMBRANE_MCP_BIN: "/fixture/mcp",
  REMBRANE_TEST_LISTEN: "127.0.0.1:19876",
  REMBRANE_DATABASE: "/fixture/real-user-database",
  REMBRANE_KEY_PROVIDER: "http",
  REMBRANE_KEY_PROVIDER_TOKEN: sentinel,
  REMBRANE_KEY_PROVIDER_BASE_URL: "https://customer.example.invalid",
  REMBRANE_WORKSPACE_KEY_HEX_REFERENCE: "file:/fixture/do-not-read",
  REMBRANE_WORKSPACE_HISTORICAL_KEYS: sentinel,
  REMBRANE_GRAPH_PROVIDER: "graphiti",
  REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT: "true",
  REMBRANE_READ_PERMISSIONS: "memory:read",
  REMBRANE_MEMORY_PROVIDER: "http",
  REMBRANE_FUTURE_PROVIDER_SECRET: sentinel,
};
const check = `
  const expected = {
    REMBRANE_BIN: "/fixture/rembrane",
    REMBRANE_API_BIN: "/fixture/api",
    REMBRANE_MCP_BIN: "/fixture/mcp",
    REMBRANE_TEST_LISTEN: "127.0.0.1:19876",
    REMBRANE_KEY_PROVIDER: "environment",
    REMBRANE_GRAPH_PROVIDER: "native",
  };
  const actual = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => name.startsWith("REMBRANE_"))
  );
  if (JSON.stringify(Object.entries(actual).sort()) !==
      JSON.stringify(Object.entries(expected).sort())) process.exit(1);
`;
const result = spawnSync(
  "/bin/sh",
  ["-eu", "-c", '. "$1"; node --input-type=module -e "$2"', "test", helper, check],
  { env: polluted, encoding: "utf8", timeout: 10_000 },
);
assert.equal(result.error, undefined);
assert.equal(result.status, 0, "local fixture environment must be isolated");
assert.equal(result.stdout, "");
assert.equal(result.stderr, "");
assert.equal(polluted.REMBRANE_KEY_PROVIDER_TOKEN, sentinel, "parent stays unchanged");

for (const script of [
  "test-cli-e2e.sh", "test-mcp-e2e.sh", "test-rest-e2e.sh",
  "test-cross-tool-continuity.sh",
]) {
  const source = readFileSync(new URL(script, import.meta.url), "utf8");
  const isolation = source.indexOf('. "$repository_root/scripts/local-test-environment.sh"');
  assert.ok(isolation >= 0, `${script} must isolate fixture configuration`);
  assert.ok(isolation < source.indexOf("rembrane_binary="), `${script} must isolate before commands`);
}
console.log("local fixture environment isolation checks passed");
