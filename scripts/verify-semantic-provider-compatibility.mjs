import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const parse = async (path) =>
  JSON.parse(await readFile(resolve(root, path), "utf8"));
const lock = await parse("spec/semantic-provider-compatibility-lock.json");
const required = new Set([
  "spec/provider-openapi.yaml",
  "spec/provider-manifest.schema.json",
  "spec/examples/provider-manifest.json",
  "spec/conformance/semantic-provider-core.json",
  "spec/semantic-provider-conformance-result.schema.json",
  "spec/examples/semantic-provider-conformance-result.json",
  "scripts/test-provider-http.sh",
]);

assert.equal(lock.lockFormat, 1, "unsupported compatibility lock format");
assert.match(lock.protocolVersion, /^\d+\.\d+$/, "invalid protocol version");
const seen = new Set();
for (const artifact of lock.artifacts) {
  assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
  assert.ok(!seen.has(artifact.path), `duplicate locked path: ${artifact.path}`);
  seen.add(artifact.path);
  const path = resolve(root, artifact.path);
  const repositoryRelative = relative(root, path);
  assert.ok(
    repositoryRelative !== ".." &&
      !repositoryRelative.startsWith(`..${sep}`) &&
      !repositoryRelative.startsWith(sep),
    `locked path escapes repository: ${artifact.path}`,
  );
  const actual = createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
  assert.equal(
    actual,
    artifact.sha256,
    `${artifact.path} changed without a reviewed compatibility-lock update`,
  );
}
assert.deepEqual(
  seen,
  required,
  "compatibility lock must contain the exact reviewed semantic-provider artifact set",
);

const manifestSchema = await parse("spec/provider-manifest.schema.json");
const manifest = await parse("spec/examples/provider-manifest.json");
const profileBytes = await readFile(
  resolve(root, "spec/conformance/semantic-provider-core.json"),
);
const profile = JSON.parse(profileBytes.toString("utf8"));
const resultSchema = await parse(
  "spec/semantic-provider-conformance-result.schema.json",
);
const result = await parse(
  "spec/examples/semantic-provider-conformance-result.json",
);
const profileSha256 = createHash("sha256").update(profileBytes).digest("hex");

assert.equal(manifest.protocolVersion, lock.protocolVersion);
assert.equal(profile.protocolVersion, lock.protocolVersion);
assert.equal(result.protocolVersion, lock.protocolVersion);
assert.equal(resultSchema.properties.protocolVersion.const, lock.protocolVersion);
assert.equal(result.suiteId, profile.profileId);
assert.equal(result.suiteVersion, profile.profileVersion);
assert.equal(result.profileSha256, profileSha256);
assert.deepEqual(
  result.cases.map(({ id }) => id),
  profile.cases.map(({ id }) => id),
  "conformance result cases differ from the reviewed profile",
);
assert.equal(
  manifestSchema.properties.protocolVersion.type,
  "string",
  "provider manifest protocol version must remain explicit",
);

process.stdout.write(
  `semantic provider compatibility lock verified (${lock.artifacts.length} artifacts)\n`,
);
