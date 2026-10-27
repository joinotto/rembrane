import assert from "node:assert/strict";
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const directory = mkdtempSync(join(tmpdir(), "rembrane-mcp-runtime-gate-"));
const scripts = join(directory, "scripts");
const bin = join(directory, "bin");
const scenarioFile = join(directory, "scenario.json");
const log = join(directory, "calls.jsonl");
mkdirSync(scripts, { mode: 0o700 });
mkdirSync(bin, { mode: 0o700 });
copyFileSync(join(root, "scripts/check-official-streamable-http.sh"),
  join(scripts, "check-official-streamable-http.sh"));
symlinkSync(join(root, "scripts/fixtures/streamable-http-runtime-cargo.mjs"),
  join(bin, "cargo"));
const base = {
  ...process.env,
  PATH: `${bin}:${process.env.PATH}`,
  REMBRANE_MCP_RUNTIME_GATE_SCENARIO: scenarioFile,
  REMBRANE_MCP_RUNTIME_GATE_CALL_LOG: log,
};
const registry = "registry+https://github.com/rust-lang/crates.io-index";
const appId = "path+file:///fixture#rembrane-mcp@0.1.0";
const sdkId = `${registry}#rmcp@3.7.0`;
const adapterId = "path+file:///fixture#rembrane-remote-mcp-http@0.1.0";
function metadata() {
  return {
    packages: [
      { name: "rembrane-mcp", id: appId, dependencies: [
        { name: "rmcp", req: "=3.7.0", source: registry, kind: null, target: null,
          optional: false, features: ["server", "transport-streamable-http-server"] },
        { name: "rembrane-remote-mcp-http", kind: null, target: null, optional: false },
      ], targets: [
        { name: "rembrane-mcp", kind: ["bin"] },
        { name: "streamable_http_runtime", kind: ["test"] },
      ] },
      { name: "rmcp", id: sdkId, version: "3.7.0", source: registry },
      { name: "rembrane-remote-mcp-http", id: adapterId },
    ],
    resolve: { nodes: [
      { id: appId, features: [], deps: [
        { name: "aliased_sdk", pkg: sdkId, dep_kinds: [{ kind: null, target: null }] },
        { name: "aliased_adapter", pkg: adapterId, dep_kinds: [{ kind: null, target: null }] },
      ] },
      { id: sdkId, features: ["server", "transport-streamable-http-server"], deps: [] },
    ] },
  };
}
let cases = 0;
function run(scenario = {}, args = ["--runtime"], success = false) {
  rmSync(log, { force: true });
  writeFileSync(scenarioFile, JSON.stringify({
    metadata: JSON.stringify(metadata()), ...scenario,
  }), { mode: 0o600 });
  const result = spawnSync("sh", [join(scripts, "check-official-streamable-http.sh"), ...args], {
    env: base, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status === 0, success, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /mcp-runtime-gate-secret/);
  const calls = existsSync(log)
    ? readFileSync(log, "utf8").trim().split("\n").map(JSON.parse) : [];
  for (const call of calls) {
    assert.ok(call.includes("--locked"));
    assert.ok(call.includes("--offline"));
    assert.ok(!call.includes("--no-deps"));
  }
  cases++;
  return calls;
}
function rejectedMetadata(change) {
  const value = metadata();
  change(value);
  assert.equal(run({ metadata: JSON.stringify(value) }).length, 1);
}
try {
  // A source marker must not stand in for an executable integration target.
  const source = join(directory, "apps/rembrane-mcp/src");
  mkdirSync(source, { recursive: true });
  writeFileSync(join(source, "lib.rs"),
    "let service = StreamableHttpService::new(fake, fake, fake);\n");
  rejectedMetadata((value) => { value.packages[0].targets.pop(); });
  assert.equal(run({}, ["--unsupported"]).length, 0);
  assert.equal(run({}, ["--build", "--runtime"]).length, 0);
  assert.equal(run({ metadataStatus: 1 }).length, 1);
  assert.equal(run({ metadata: "not-json" }).length, 1);
  rejectedMetadata((value) => { value.resolve = null; });
  rejectedMetadata((value) => { value.packages[0].name = "unrelated"; });
  rejectedMetadata((value) => { value.packages.push(value.packages[0]); });
  rejectedMetadata((value) => { value.resolve.nodes.pop(); });
  rejectedMetadata((value) => { value.resolve.nodes.push(value.resolve.nodes[0]); });
  rejectedMetadata((value) => { value.resolve.nodes.push(value.resolve.nodes[1]); });
  rejectedMetadata((value) => { value.packages[1].version = "3.7.1"; });
  rejectedMetadata((value) => { value.packages[1].source = null; });
  rejectedMetadata((value) => { value.packages[1].source = "git+https://example.invalid/sdk"; });
  rejectedMetadata((value) => { value.packages[1].source = "registry+https://example.invalid/index"; });
  rejectedMetadata((value) => { value.packages[2].name = "pretend-adapter"; });
  rejectedMetadata((value) => { value.packages[0].dependencies[0].req = "^3.7.0"; });
  rejectedMetadata((value) => { value.packages[0].dependencies[0].source = null; });
  rejectedMetadata((value) => { value.packages[0].dependencies[0].features = ["server"]; });
  rejectedMetadata((value) => { value.resolve.nodes[1].features = ["server"]; });
  for (const index of [0, 1]) {
    rejectedMetadata((value) => { value.packages[0].dependencies.splice(index, 1); });
    rejectedMetadata((value) => { value.packages[0].dependencies[index].kind = "dev"; });
    rejectedMetadata((value) => { value.packages[0].dependencies[index].kind = "build"; });
    rejectedMetadata((value) => { value.packages[0].dependencies[index].optional = true; });
    rejectedMetadata((value) => { value.packages[0].dependencies[index].target = "cfg(unix)"; });
    rejectedMetadata((value) => { value.resolve.nodes[0].deps.splice(index, 1); });
    rejectedMetadata((value) => { value.resolve.nodes[0].deps[index].dep_kinds[0].kind = "dev"; });
    rejectedMetadata((value) => { value.resolve.nodes[0].deps[index].dep_kinds[0].kind = "build"; });
    rejectedMetadata((value) => { value.resolve.nodes[0].deps[index].dep_kinds[0].target = "cfg(unix)"; });
  }
  for (const index of [0, 1]) {
    rejectedMetadata((value) => { value.packages[0].targets.splice(index, 1); });
    rejectedMetadata((value) => { value.packages[0].targets[index].kind = ["example"]; });
    rejectedMetadata((value) => { value.packages[0].targets[index]["required-features"] = ["disabled"]; });
  }
  assert.equal(run({ binaryStatus: 1 }, ["--build"]).length, 2);
  assert.equal(run({ testBuildStatus: 1 }, ["--build"]).length, 3);
  const buildCalls = run({}, ["--build"], true);
  assert.equal(buildCalls.length, 3);
  assert.deepEqual(buildCalls.slice(1).map((args) => args.slice(0, 5)), [
    ["check", "--package", "rembrane-mcp", "--bin", "rembrane-mcp"],
    ["check", "--package", "rembrane-mcp", "--test", "streamable_http_runtime"],
  ]);
  const enabled = metadata();
  enabled.resolve.nodes[0].features = ["runtime"];
  for (const target of enabled.packages[0].targets) target["required-features"] = ["runtime"];
  assert.equal(run({ metadata: JSON.stringify(enabled) }, ["--build"], true).length, 3);
  for (const testOutput of [
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s",
    "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 7 filtered out; finished in 0.00s",
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.00s",
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s",
    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s\n"
      + "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s",
    "no libtest result",
  ]) {
    assert.equal(run({ testOutput }).length, 4);
  }
  assert.equal(run({ testStatus: 1 }).length, 4);
  const testNames = [
    "sdk_http_two_tenant_encrypted_context_lifecycle",
    "sdk_http_denies_cross_tenant_and_scope_substitution",
    "sdk_http_session_initialization_and_confirmation",
    "sdk_http_session_replacement_and_late_cleanup",
    "sdk_http_queued_tool_expiry_and_revocation",
    "sdk_http_stream_expiry_and_revocation",
    "sdk_http_bounded_admission_and_cancellation",
    "sdk_http_redacts_transport_and_provider_failures",
  ];
  for (const [index, failTest] of testNames.entries()) {
    assert.equal(run({ failTest }).length, 4 + index);
  }
  const calls = run({}, [], true);
  assert.equal(calls.length, 11);
  assert.deepEqual(calls.slice(3).map((args) => args[args.indexOf("--") + 1]), testNames);
  for (const args of calls.slice(3)) {
    assert.ok(args.includes("--exact"));
    assert.ok(args.includes("--include-ignored"));
    assert.equal(args[args.indexOf("--test") + 1], "streamable_http_runtime");
  }
  console.log(`Official MCP HTTP runtime gate: ${cases} cases passed (no compilation/SDK runtime proof)`);
} finally {
  rmSync(directory, { recursive: true, force: true });
}
