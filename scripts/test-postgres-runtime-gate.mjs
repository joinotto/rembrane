import assert from "node:assert/strict";
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const directory = mkdtempSync(join(tmpdir(), "rembrane-runtime-gate-"));
const scripts = join(directory, "scripts");
const bin = join(directory, "bin");
const scenarioFile = join(directory, "scenario.json");
const log = join(directory, "calls.jsonl");
const admin = join(directory, "admin.conf");
const runtime = join(directory, "runtime.conf");
mkdirSync(scripts, { mode: 0o700 });
mkdirSync(bin, { mode: 0o700 });
for (const file of ["check-postgres-runtime-adapter.sh", "check-postgres-fixture-service.mjs"]) {
  copyFileSync(join(root, "scripts", file), join(scripts, file));
}
symlinkSync(join(root, "scripts/fixtures/postgres-runtime-cargo.mjs"), join(bin, "cargo"));
for (const profile of [admin, runtime]) {
  writeFileSync(profile, "fixture-only-private-profile", { mode: 0o600 });
}
const base = {
  ...process.env,
  PATH: `${bin}:${process.env.PATH}`,
  REMBRANE_RUNTIME_GATE_SCENARIO: scenarioFile,
  REMBRANE_RUNTIME_GATE_CALL_LOG: log,
  REMBRANE_POSTGRES_TEST_SERVICE_FILE: admin,
  REMBRANE_POSTGRES_RUNTIME_URL_FILE: runtime,
  REMBRANE_POSTGRES_TEST_DATABASE: "rembrane_test_gate",
  REMBRANE_POSTGRES_TEST_CONFIRM: "disposable-empty-database",
};
const adapterId = "path+file:///fixture#rembrane-store-postgres@0.1.0";
const driverId = "registry+https://example.invalid#postgres@0.19.0";
function metadata() {
  return {
    packages: [
      { name: "rembrane-store-postgres", id: adapterId, targets: [
        { name: "postgres_runtime", kind: ["test"] },
      ] },
      { name: "postgres", id: driverId },
    ],
    resolve: { nodes: [
      { id: adapterId, features: [], deps: [
        { name: "aliased_driver", pkg: driverId, dep_kinds: [{ kind: null, target: null }] },
      ] },
    ] },
  };
}
let cases = 0;
function run(scenario, mode = "--build", env = {}, success = false) {
  rmSync(log, { force: true });
  writeFileSync(scenarioFile, JSON.stringify({
    metadata: JSON.stringify(metadata()), ...scenario,
  }));
  const result = spawnSync("sh", [join(scripts, "check-postgres-runtime-adapter.sh"), mode], {
    env: { ...base, ...env }, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status === 0, success, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /runtime-gate-secret/);
  const calls = existsSync(log)
    ? readFileSync(log, "utf8").trim().split("\n").map(JSON.parse) : [];
  for (const call of calls) {
    assert.ok(call.includes("--locked"));
    assert.ok(call.includes("--offline"));
    assert.doesNotMatch(JSON.stringify(call), /password|postgresql:/);
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
  assert.equal(run({}, "--unsupported").length, 0);
  assert.equal(run({ metadataStatus: 1 }).length, 1);
  assert.equal(run({ metadata: "not-json" }).length, 1);
  rejectedMetadata((value) => { value.packages[0].name = "unrelated"; });
  rejectedMetadata((value) => { value.packages.push(value.packages[0]); });
  rejectedMetadata((value) => { value.packages[1].name = "pretend-postgres"; });
  rejectedMetadata((value) => { value.resolve.nodes[0].deps = []; });
  rejectedMetadata((value) => { value.resolve.nodes[0].deps[0].dep_kinds[0].kind = "dev"; });
  rejectedMetadata((value) => { value.resolve.nodes[0].deps[0].dep_kinds[0].kind = "build"; });
  rejectedMetadata((value) => { value.resolve.nodes[0].deps[0].dep_kinds[0].target = "cfg(unix)"; });
  rejectedMetadata((value) => { value.packages[0].targets = []; });
  rejectedMetadata((value) => { value.packages[0].targets[0].kind = ["example"]; });
  rejectedMetadata((value) => { value.packages[0].targets[0]["required-features"] = ["disabled"]; });
  assert.equal(run({ buildStatus: 1 }).length, 2);
  assert.equal(run({}, "--build", {}, true).length, 2);
  const defaultFeature = metadata();
  defaultFeature.resolve.nodes[0].features = ["runtime"];
  defaultFeature.packages[0].targets[0]["required-features"] = ["runtime"];
  assert.equal(run({ metadata: JSON.stringify(defaultFeature) }, "--build", {}, true).length, 2);
  for (const env of [
    { REMBRANE_POSTGRES_TEST_CONFIRM: "" },
    { REMBRANE_POSTGRES_TEST_DATABASE: "production" },
    { REMBRANE_POSTGRES_TEST_DATABASE: "rembrane_test_" },
    { REMBRANE_POSTGRES_TEST_DATABASE: "rembrane_test_a;DROP" },
    { REMBRANE_POSTGRES_TEST_DATABASE: `rembrane_test_${"x".repeat(60)}` },
    { REMBRANE_POSTGRES_RUNTIME_URL_FILE: "" },
    { REMBRANE_POSTGRES_RUNTIME_URL_FILE: admin },
    { REMBRANE_POSTGRES_RUNTIME_URL_FILE: join(directory, "absent") },
  ]) {
    assert.equal(run({}, "--live", env).length, 2);
  }
  for (const testOutput of [
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s",
    "test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 4 filtered out; finished in 0.00s",
    "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.00s",
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.00s",
    "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.00s\n"
      + "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s",
    "no libtest result",
  ]) {
    assert.equal(run({ testOutput }, "--live").length, 3);
  }
  assert.equal(run({ testStatus: 1 }, "--live").length, 3);
  const testNames = [
    "runtime_pool_two_tenant_lifecycle",
    "runtime_pool_connection_reset_after_rollback_and_error",
    "runtime_pool_rejects_unsafe_authority",
    "runtime_pool_atomicity_and_cancellation",
    "runtime_pool_redacts_driver_errors",
  ];
  for (const [index, failTest] of testNames.entries()) {
    assert.equal(run({ failTest }, "--live").length, 3 + index);
  }
  const calls = run({}, "--live", {}, true);
  assert.equal(calls.length, 7);
  assert.deepEqual(calls.slice(2).map((args) => args[args.indexOf("--") + 1]), testNames);
  for (const args of calls.slice(2)) {
    assert.ok(args.includes("--exact"));
    assert.ok(args.includes("--include-ignored"));
    assert.equal(args[args.indexOf("--test") + 1], "postgres_runtime");
  }
  console.log(`PostgreSQL runtime gate: ${cases} cases passed (no compilation/database proof)`);
} finally {
  rmSync(directory, { recursive: true, force: true });
}
