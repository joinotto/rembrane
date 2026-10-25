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
const expectedArtifacts = [
  "spec/memory-provider.schema.json",
  "spec/memory-provider-openapi.yaml",
  "spec/memory-provider-conformance.schema.json",
  "spec/memory-provider-conformance-result.schema.json",
  "spec/memory-provider-fixtures.schema.json",
  "spec/conformance/memory-provider-core.json",
  "spec/conformance/memory-provider-core-fixtures.json",
  "spec/examples/memory-provider-conformance-result.json",
];
assert.deepEqual(
  lock.artifacts.map((artifact) => artifact.path).sort(),
  expectedArtifacts.sort(),
  "memory provider compatibility lock has an unexpected artifact set",
);

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
const conformanceSchema = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/memory-provider-conformance.schema.json"),
    "utf8",
  ),
);
const resultSchema = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/memory-provider-conformance-result.schema.json"),
    "utf8",
  ),
);
const fixtureSchema = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/memory-provider-fixtures.schema.json"),
    "utf8",
  ),
);
const profile = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/conformance/memory-provider-core.json"),
    "utf8",
  ),
);
const fixtures = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/conformance/memory-provider-core-fixtures.json"),
    "utf8",
  ),
);
const resultFixture = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/examples/memory-provider-conformance-result.json"),
    "utf8",
  ),
);
assert.equal(
  schema.$defs.protocolVersion.const,
  lock.protocolVersion,
  "compatibility lock and canonical schema protocol versions differ",
);
assert.equal(
  conformanceSchema.properties.profileId.const,
  profile.profileId,
  "conformance schema is bound to a different profile",
);
assert.equal(
  fixtureSchema.properties.profileId.const,
  profile.profileId,
  "fixture schema is bound to a different profile",
);
assert.equal(
  resultSchema.properties.profileId.const,
  profile.profileId,
  "result schema is bound to a different profile",
);
assert.equal(
  fixtures.profileId,
  profile.profileId,
  "fixture corpus is bound to a different profile",
);
assert.equal(
  resultFixture.profileId,
  profile.profileId,
  "result fixture is bound to a different profile",
);
assert.equal(
  fixtureSchema.properties.fixtureId.const,
  fixtures.fixtureId,
  "fixture schema is bound to a different fixture corpus",
);
assert.equal(
  resultSchema.properties.fixtureId.const,
  fixtures.fixtureId,
  "result schema is bound to a different fixture corpus",
);
assert.equal(
  resultFixture.fixtureId,
  fixtures.fixtureId,
  "result fixture is bound to a different fixture corpus",
);
for (const artifact of [
  conformanceSchema,
  resultSchema,
  fixtureSchema,
  profile,
  fixtures,
  resultFixture,
]) {
  assert.equal(
    artifact.protocolVersion ??
      artifact.properties?.protocolVersion?.const,
    lock.protocolVersion,
    "locked memory-provider artifact protocol versions differ",
  );
}

process.stdout.write(
  `memory provider compatibility lock verified (${lock.artifacts.length} artifacts)\n`,
);
