import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

// Check the shell runner's exact output expectations only. This does not
// execute SQL or establish database/RLS behavior.
const source = readFileSync(new URL("./test-postgres-rls.sh", import.meta.url), "utf8");
const expected = source.match(/test "\$result" = "([^"]+)"/)?.[1];
assert.equal(typeof expected, "string", "scoped result assertion must exist");
const counts = "1|1|1|1|1|1|1|1|1|1|1|1|1|2|1|1|1|1|1";
const output = `workspace_01\n${counts}`;
const check = (actual, expectation = expected) => {
  const result = spawnSync("/bin/sh", [
    "-c", 'test "$1" = "$2"', "fixture-result", actual, expectation,
  ], { encoding: "utf8", timeout: 5_000 });
  assert.equal(result.error, undefined);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
  return result.status;
};
assert.equal(check(output), 0, "scoped assertion must include set_config's result row");
for (const invalid of [
  counts,
  `workspace_02\n${counts}`,
  `${output}\nunexpected`,
  `${output}\n${counts}`,
  `workspace_01\n${counts.replace(/^1/, "2")}`,
  "",
]) {
  assert.notEqual(check(invalid), 0, "binding, counts and extra rows must fail closed");
}
assert.match(source, /SELECT set_config\('rembrane\.workspace_id', 'workspace_01', true\);/);
assert.match(source, /test "\$unscoped" = "0(?:\|0){18}"/);
assert.match(source, /test "\$pooled_connection_result" = "workspace_01\n1\n0"/);
const writeExpected = source.match(/test "\$cross_tenant_write_proof" = "([^"]+)"/)?.[1];
assert.equal(typeof writeExpected, "string");
const writeOutput = "workspace_01\ncross-tenant-writes-denied";
assert.equal(check(writeOutput, writeExpected), 0);
for (const invalid of [
  "cross-tenant-writes-denied",
  "workspace_02\ncross-tenant-writes-denied",
  `${writeOutput}\nunexpected`,
  `${writeOutput}\ncross-tenant-writes-denied`,
  "workspace_01\nPostgreSQL fixture command failed",
  "",
]) {
  assert.notEqual(check(invalid, writeExpected), 0);
}
assert.doesNotMatch(source, /if fixture_psql(?:\s|>)/);
assert.match(source, /EXCEPTION WHEN insufficient_privilege THEN/);
assert.doesNotMatch(source, /EXCEPTION WHEN OTHERS/);
assert.match(source, /same-tenant update control failed/);
assert.match(source, /same-tenant delete control failed/);
assert.match(source, /RLS accepted a cross-tenant update/);
assert.match(source, /RLS accepted a cross-tenant delete/);
console.log("PostgreSQL fixture output: fourteen exact-result cases passed (no SQL/RLS proof)");
