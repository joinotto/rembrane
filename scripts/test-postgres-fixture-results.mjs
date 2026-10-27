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
const check = (actual) => {
  const result = spawnSync("/bin/sh", [
    "-c", 'test "$1" = "$2"', "fixture-result", actual, expected,
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
console.log("PostgreSQL fixture output: seven exact-result cases passed (no SQL/RLS proof)");
