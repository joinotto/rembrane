import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const lock = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/key-provider-compatibility-lock.json"),
    "utf8",
  ),
);

assert.equal(lock.lockFormat, 1, "unsupported compatibility lock format");
assert.match(lock.protocolVersion, /^\d+\.\d+$/, "invalid protocol version");
assert.ok(Array.isArray(lock.artifacts) && lock.artifacts.length > 0);

const seenPaths = new Set();
const requiredArtifacts = new Set([
  "spec/key-provider-openapi.yaml",
  "spec/examples/key-provider-manifest.json",
  "spec/key-provider-conformance.schema.json",
  "spec/conformance/key-provider-core.json",
  "spec/key-provider-conformance-result.schema.json",
  "spec/examples/key-provider-conformance-result.json",
  "scripts/test-key-provider-http.sh",
]);
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
  assert.ok(
    artifact.path.startsWith("spec/") || artifact.path.startsWith("scripts/"),
    `locked path is outside protocol surfaces: ${artifact.path}`,
  );

  const contents = await readFile(artifactPath);
  const actual = createHash("sha256").update(contents).digest("hex");
  assert.equal(
    actual,
    artifact.sha256,
    `${artifact.path} changed without a reviewed compatibility-lock update`,
  );
}
assert.deepEqual(
  seenPaths,
  requiredArtifacts,
  "compatibility lock must contain the exact reviewed key-provider artifact set",
);

const openapi = await readFile(
  resolve(repositoryRoot, "spec/key-provider-openapi.yaml"),
  "utf8",
);
assert.ok(
  openapi.includes(`version: ${lock.protocolVersion}.0`),
  "compatibility lock and key-provider OpenAPI versions differ",
);
const manifest = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/examples/key-provider-manifest.json"),
    "utf8",
  ),
);
const resultSchema = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/key-provider-conformance-result.schema.json"),
    "utf8",
  ),
);
const conformanceSchema = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/key-provider-conformance.schema.json"),
    "utf8",
  ),
);
const conformanceProfile = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/conformance/key-provider-core.json"),
    "utf8",
  ),
);
const resultFixture = JSON.parse(
  await readFile(
    resolve(repositoryRoot, "spec/examples/key-provider-conformance-result.json"),
    "utf8",
  ),
);
assert.equal(
  manifest.protocolVersion,
  lock.protocolVersion,
  "compatibility lock and discovery fixture protocol versions differ",
);
assert.equal(
  conformanceSchema.properties.protocolVersion.const,
  lock.protocolVersion,
  "compatibility lock and conformance profile schema versions differ",
);
assert.equal(
  conformanceProfile.protocolVersion,
  lock.protocolVersion,
  "compatibility lock and conformance profile versions differ",
);
assert.equal(
  resultSchema.properties.protocolVersion.const,
  lock.protocolVersion,
  "compatibility lock and conformance schema protocol versions differ",
);
assert.equal(
  resultFixture.protocolVersion,
  lock.protocolVersion,
  "compatibility lock and conformance fixture protocol versions differ",
);

process.stdout.write(
  `key provider compatibility lock verified (${lock.artifacts.length} artifacts)\n`,
);
