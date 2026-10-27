import assert from "node:assert/strict";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const directory = mkdtempSync(join(tmpdir(), "rembrane-postgres-guard-"));
const profile = join(directory, "service.conf");
const log = join(directory, "calls.jsonl");
const bin = join(directory, "bin");
mkdirSync(bin, { mode: 0o700 });
symlinkSync(resolve(root, "scripts/fixtures/postgres-fixture-psql.mjs"), join(bin, "psql"));
writeFileSync(profile, "[rembrane_fixture]\npassword=fixture-secret-must-not-leak\n", { mode: 0o600 });
const base = {
  ...process.env,
  PATH: `${bin}:${process.env.PATH}`,
  REMBRANE_POSTGRES_TEST_CONFIRM: "disposable-empty-database",
  REMBRANE_POSTGRES_TEST_DATABASE: "rembrane_test_guard",
  REMBRANE_POSTGRES_TEST_SERVICE_FILE: profile,
  REMBRANE_FIXTURE_CALL_LOG: log,
  REMBRANE_FIXTURE_PROOF: "rembrane_test_guard|empty|role-clear",
  REMBRANE_POSTGRES_URL: "postgresql://secret-should-not-be-used",
};
let cases = 0;
function run(overrides, expectedCalls) {
  rmSync(log, { force: true });
  const result = spawnSync("sh", ["scripts/test-postgres-rls.sh"], {
    cwd: root, env: { ...base, ...overrides }, encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0, "fake must never pass the RLS suite");
  const calls = existsSync(log)
    ? readFileSync(log, "utf8").trim().split("\n").map(JSON.parse) : [];
  assert.equal(calls.length, expectedCalls);
  assert.doesNotMatch(result.stdout + result.stderr, /fixture-secret|secret-should/);
  for (const call of calls) {
    assert.equal(call.service, "rembrane_fixture");
    assert.equal(call.serviceFile, profile);
    assert.ok(call.args.includes("-X"));
    assert.ok(call.args.includes("-w"));
    assert.ok(call.args.includes("ON_ERROR_STOP=1"));
    assert.doesNotMatch(JSON.stringify(call.args), /postgresql:|password|secret-should/);
  }
  if (calls.length) {
    assert.equal(calls[0].probe, true);
    assert.match(calls[0].args.at(-1), /BEGIN TRANSACTION READ ONLY/);
    assert.doesNotMatch(calls[0].args.at(-1), /\b(?:DROP|CREATE|INSERT|DELETE|UPDATE)\b/);
  }
  cases++;
  return calls;
}
try {
  for (const confirm of ["", "yes", "production"]) {
    run({ REMBRANE_POSTGRES_TEST_CONFIRM: confirm }, 0);
  }
  for (const name of ["", "postgres", "rembrane_test_", "rembrane_test_X",
    "rembrane_test_foo;DROP", `rembrane_test_${"x".repeat(60)}`]) {
    run({ REMBRANE_POSTGRES_TEST_DATABASE: name }, 0);
  }
  for (const file of ["", join(directory, "absent"), "relative.conf", directory]) {
    run({ REMBRANE_POSTGRES_TEST_SERVICE_FILE: file }, 0);
  }
  const link = join(directory, "service-link");
  symlinkSync(profile, link);
  run({ REMBRANE_POSTGRES_TEST_SERVICE_FILE: link }, 0);
  for (const mode of [0o644, 0o640, 0o700]) {
    chmodSync(profile, mode);
    run({}, 0);
  }
  chmodSync(profile, 0o600);
  const empty = join(directory, "empty");
  const oversized = join(directory, "oversized");
  const fifo = join(directory, "fifo");
  writeFileSync(empty, "", { mode: 0o600 });
  writeFileSync(oversized, "x".repeat(65_537), { mode: 0o600 });
  assert.equal(spawnSync("mkfifo", [fifo]).status, 0);
  run({ REMBRANE_POSTGRES_TEST_SERVICE_FILE: empty }, 0);
  run({ REMBRANE_POSTGRES_TEST_SERVICE_FILE: oversized }, 0);
  run({ REMBRANE_POSTGRES_TEST_SERVICE_FILE: fifo }, 0);
  for (const proof of [
    "postgres|empty|role-clear", "rembrane_test_guard|occupied|role-clear",
    "rembrane_test_guard|empty|role-present", "", "fail",
    "rembrane_test_guard|empty|role-clear\nunexpected",
  ]) {
    run({ REMBRANE_FIXTURE_PROOF: proof }, 1);
  }
  const calls = run({}, 2);
  assert.equal(calls[1].probe, false);
  assert.ok(calls[1].args.includes("migrations/postgres/0001_canonical_schema.sql"));
  chmodSync(profile, 0o400);
  run({}, 2);
  const source = readFileSync(join(root, "scripts/test-postgres-rls.sh"), "utf8");
  assert.doesNotMatch(source, /DROP (?:SCHEMA|TABLE|ROLE)/);
  assert.equal((source.match(/\bpsql -X/g) || []).length, 1);
  console.log(`PostgreSQL fixture guard: ${cases} cases passed (no live database proof)`);
} finally {
  rmSync(directory, { recursive: true, force: true });
}
