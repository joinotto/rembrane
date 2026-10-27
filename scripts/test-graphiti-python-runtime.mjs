import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("./graphiti-python-runtime.sh", import.meta.url));
const directory = await mkdtemp(join(tmpdir(), "rembrane-python-selection-"));
const environment = { ...process.env, PATH: directory };
delete environment.REMBRANE_GRAPHITI_PYTHON;
const interpreter = async (name, status) => {
  const path = join(directory, name);
  await writeFile(path, `#!/bin/sh\nexit ${status}\n`, { mode: 0o700 });
  return path;
};
const select = (overrides = {}) => spawnSync(
  "/bin/sh", ["-eu", "-c", '. "$1"; rembrane_graphiti_python', "test", helper],
  { env: { ...environment, ...overrides }, encoding: "utf8", timeout: 5_000 },
);
const expectSelected = (name, overrides) => {
  const result = select(overrides);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${name}\n`);
  assert.equal(result.stderr, "");
};

try {
  const missing = select();
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /Python 3\.11 or newer/);
  await interpreter("python3.13", 0);
  expectSelected("python3.13");
  await interpreter("python3", 0);
  expectSelected("python3");
  await interpreter("python", 0);
  expectSelected("python");
  await interpreter("python", 1);
  expectSelected("python3");
  const explicit = await interpreter("selected python", 0);
  expectSelected(explicit, { REMBRANE_GRAPHITI_PYTHON: explicit });
  await interpreter("selected python", 1);
  const invalid = select({ REMBRANE_GRAPHITI_PYTHON: explicit });
  assert.equal(invalid.status, 1, "invalid explicit selection must not fall back");
  assert.equal(invalid.stdout, "");
  assert.match(invalid.stderr, /selected Graphiti Python/);
  for (const name of ["test-graphiti-sidecar.sh", "test-graphiti-http-e2e.sh"]) {
    const source = await readFile(new URL(name, import.meta.url), "utf8");
    assert.ok(source.includes('. "$repository_root/scripts/graphiti-python-runtime.sh"'));
    assert.ok(source.includes("python_runtime=$(rembrane_graphiti_python)"));
  }
  console.log("Graphiti interpreter selection: seven isolated fixture cases passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}
