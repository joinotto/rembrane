import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";

// Check the shell runner's exact output expectations only. This does not
// execute SQL or establish database/RLS behavior.
const source = readFileSync(new URL("./test-postgres-rls.sh", import.meta.url), "utf8");
const countQuery = readFileSync(new URL("./postgres-fixture-counts.sql", import.meta.url), "utf8");
const counted = [...countQuery.matchAll(/\(SELECT count\(\*\) FROM ([a-z_]+)\)/g)]
  .map((match) => match[1]);
const migrations = new URL("../migrations/postgres/", import.meta.url);
const tables = readdirSync(migrations)
  .filter((name) => /^0\d+_.+\.sql$/.test(name))
  .flatMap((name) => [...readFileSync(new URL(name, migrations), "utf8")
    .matchAll(/^CREATE TABLE ([a-z_]+) \(/gm)].map((match) => match[1]));
const seed = source.match(/fixture_psql <<'SQL'\n([\s\S]*?)\nSQL\n/)?.[1];
assert.equal(typeof seed, "string");
const seeded = [...seed.matchAll(/INSERT INTO ([a-z_]+) \(/g)].map((match) => match[1]);
const identities = [...countQuery.matchAll(/\('([a-z_]+)', '(?:workspace_id|id|source_workspace_id)'\)/g)]
  .map((match) => match[1]);
identities.push("principals");
function inventory(actual) {
  assert.deepEqual([...actual].sort(), [...tables].sort(), "fixture must cover every migrated table once");
}
inventory(counted);
inventory(seeded);
inventory(identities);
assert.equal(counted.length, 32, "review count expectations when the schema changes");
assert.throws(() => inventory(counted.slice(1)));
assert.throws(() => inventory([...counted, "future_uncovered_table"]));
assert.throws(() => inventory([...counted.slice(1), counted[1]]));
assert.equal((source.match(/^\s*-f scripts\/postgres-fixture-counts\.sql \\/gm) || []).length, 3);
const expected = source.match(/test "\$result" = "([^"]+)"/)?.[1];
assert.equal(typeof expected, "string", "scoped result assertion must exist");
const counts = counted.map((table) =>
  ["principals", "memberships", "knowledge_nodes"].includes(table) ? 2 : 1,
).join("|");
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
  `workspace_01\n${counts.replace(/^2/, "3")}`,
  "",
]) {
  assert.notEqual(check(invalid), 0, "binding, counts and extra rows must fail closed");
}
assert.match(source, /SELECT set_config\('rembrane\.workspace_id', 'workspace_01', true\);/);
const otherExpected = source.match(/test "\$other_result" = "([^"]+)"/)?.[1];
assert.equal(typeof otherExpected, "string");
const otherOutput = `workspace_02\n${counts}`;
assert.equal(check(otherOutput, otherExpected), 0);
for (const invalid of [
  counts, output, `${otherOutput}\nunexpected`, `${otherOutput}\n${counts}`,
  `workspace_02\n${counts.replace(/^2/, "3")}`, "",
]) {
  assert.notEqual(check(invalid, otherExpected), 0);
}
const unscopedExpected = source.match(/test "\$unscoped" = "([^"]+)"/)?.[1];
assert.equal(typeof unscopedExpected, "string");
const unscopedOutput = counted.map(() => 0).join("|");
assert.equal(check(unscopedOutput, unscopedExpected), 0);
for (const invalid of [
  counts, `workspace_01\n${unscopedOutput}`, `${unscopedOutput}\nunexpected`,
  `${unscopedOutput}\n${unscopedOutput}`, unscopedOutput.replace(/^0/, "1"), "",
]) {
  assert.notEqual(check(invalid, unscopedExpected), 0);
}
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
assert.match(countQuery, /%I IS DISTINCT FROM/);
assert.match(countQuery, /WHERE membership\.principal_id = principal\.id/);
assert.match(countQuery, /membership\.workspace_id =/);
console.log("PostgreSQL fixture inventory: 32 tables, three refusal cases, 28 output cases (no SQL/RLS proof)");
