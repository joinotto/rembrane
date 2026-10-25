import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const lockPath = resolve(
  repositoryRoot,
  "spec/memory-provider-compatibility-lock.json",
);
const lock = JSON.parse(await readFile(lockPath, "utf8"));

assert.equal(lock.lockFormat, 1, "unsupported compatibility lock format");
assert.match(lock.protocolVersion, /^\d+\.\d+$/, "invalid protocol version");
assert.ok(Array.isArray(lock.artifacts) && lock.artifacts.length > 0);

const seenPaths = new Set();
for (const artifact of lock.artifacts) {
  assert.equal(typeof artifact.path, "string");
  assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
  assert.ok(!seenPaths.has(artifact.path), `duplicate locked path: ${artifact.path}`);
  seenPaths.add(artifact.path);

  const artifactPath = resolve(repositoryRoot, artifact.path);
  const repositoryRelative = relative(repositoryRoot, artifactPath);
  assert.ok(
    repositoryRelative !== ".." &&
      !repositoryRelative.startsWith(`..${sep}`) &&
      !repositoryRelative.startsWith(sep),
    `locked path escapes repository: ${artifact.path}`,
  );

  const contents = await readFile(artifactPath);
  const actual = createHash("sha256").update(contents).digest("hex");
  assert.equal(
    actual,
    artifact.sha256,
    `${artifact.path} changed without a reviewed compatibility-lock update`,
  );
}

const schema = JSON.parse(
  await readFile(resolve(repositoryRoot, "spec/memory-provider.schema.json"), "utf8"),
);
assert.equal(
  schema.$defs.protocolVersion.const,
  lock.protocolVersion,
  "compatibility lock and canonical schema protocol versions differ",
);

process.stdout.write(
  `memory provider compatibility lock verified (${lock.artifacts.length} artifacts)\n`,
);
