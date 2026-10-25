import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [input, externalPublicKeyInput, ...options] = process.argv.slice(2);
const verifyRepository = options.includes("--verify-repository");
if (
  !input ||
  !externalPublicKeyInput ||
  options.some((option) => option !== "--verify-repository")
) {
  throw new Error(
    "usage: verify-memory-provider-release-evidence.mjs EVIDENCE_DIRECTORY EXTERNAL_PUBLIC_KEY [--verify-repository]",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(process.cwd(), input);
requireDirectory(root);
requireExactEntries(root, [
  "compatibility-lock.json",
  "manifest.json",
  "migration.md",
  "mixed-version.json",
  "provider-a.json",
  "provider-b.json",
  "provider-b.provenance.json",
  "provider-b.provenance.json.sig",
]);

const manifestBytes = readBoundedFile(
  join(root, "manifest.json"),
  64 * 1024,
  "manifest",
);
const mixedBytes = readBoundedFile(
  join(root, "mixed-version.json"),
  128 * 1024,
  "mixed-version evidence",
);
const packagedLockBytes = readBoundedFile(
  join(root, "compatibility-lock.json"),
  128 * 1024,
  "compatibility lock",
);
const packagedMigrationBytes = readBoundedFile(
  join(root, "migration.md"),
  256 * 1024,
  "migration notes",
);
const canonicalLockBytes = readFileSync(
  join(repositoryRoot, "spec/memory-provider-compatibility-lock.json"),
);
const canonicalMigrationBytes = readFileSync(
  join(repositoryRoot, "spec/MEMORY_PROVIDER_0.1_TO_1.0_MIGRATION.md"),
);
const profileBytes = readFileSync(
  join(repositoryRoot, "spec/conformance/memory-provider-core.json"),
);
const fixtureBytes = readFileSync(
  join(repositoryRoot, "spec/conformance/memory-provider-core-fixtures.json"),
);
const externalPublicKeyPath = resolve(process.cwd(), externalPublicKeyInput);
const externalPublicKeyBytes = readBoundedFile(
  externalPublicKeyPath,
  16 * 1024,
  "external public key",
);
const externalProvenanceBytes = readBoundedFile(
  join(root, "provider-b.provenance.json"),
  16 * 1024,
  "external provider provenance",
);
const externalSignatureBytes = readBoundedFile(
  join(root, "provider-b.provenance.json.sig"),
  64,
  "external provider provenance signature",
);
const profile = JSON.parse(profileBytes.toString("utf8"));
const manifest = parseObject(manifestBytes, "manifest");

requireExactKeys(manifest, [
  "candidateProtocolVersion",
  "candidateSourceRevision",
  "compatibilityLockSha256",
  "externalPublicKeySha256",
  "externalProvenanceSha256",
  "externalProvenanceSignatureSha256",
  "fixtureSha256",
  "generatedAt",
  "mixedVersionEvidenceSha256",
  "migrationNotesSha256",
  "profileSha256",
  "providers",
  "schemaVersion",
]);
if (
  manifest.schemaVersion !== 1 ||
  !/^[0-9a-f]{40}$/.test(manifest.candidateSourceRevision) ||
  canonicalTimestamp(manifest.generatedAt) === undefined ||
  canonicalTimestamp(manifest.generatedAt) > Date.now() + 5 * 60 * 1000 ||
  manifest.candidateProtocolVersion !== profile.protocolVersion ||
  manifest.candidateProtocolVersion !==
    parseObject(packagedLockBytes, "compatibility lock").protocolVersion ||
  manifest.profileSha256 !== sha256(profileBytes) ||
  manifest.fixtureSha256 !== sha256(fixtureBytes) ||
  manifest.externalPublicKeySha256 !== sha256(externalPublicKeyBytes) ||
  manifest.externalProvenanceSha256 !== sha256(externalProvenanceBytes) ||
  manifest.externalProvenanceSignatureSha256 !== sha256(externalSignatureBytes) ||
  manifest.compatibilityLockSha256 !== sha256(packagedLockBytes) ||
  manifest.migrationNotesSha256 !== sha256(packagedMigrationBytes) ||
  !packagedLockBytes.equals(canonicalLockBytes) ||
  !packagedMigrationBytes.equals(canonicalMigrationBytes) ||
  manifest.mixedVersionEvidenceSha256 !== sha256(mixedBytes) ||
  !Array.isArray(manifest.providers) ||
  manifest.providers.length !== 2
) {
  throw new Error("memory-provider release evidence manifest is invalid");
}

if (verifyRepository) {
  const status = execFileSync("git", ["status", "--porcelain=v1", "-z"], {
    cwd: repositoryRoot,
  });
  const revision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  }).trim();
  if (status.length !== 0 || manifest.candidateSourceRevision !== revision) {
    throw new Error(
      "memory-provider release evidence does not match a clean repository",
    );
  }
}

const mixedVerifier = join(
  repositoryRoot,
  "scripts/verify-memory-provider-mixed-version-evidence.mjs",
);
const mixedVerification = spawnSync(
  process.execPath,
  [mixedVerifier, join(root, "mixed-version.json")],
  { encoding: "utf8" },
);
if (mixedVerification.status !== 0) {
  throw new Error(
    `memory-provider mixed-version evidence failed verification: ${boundedError(
      mixedVerification.stderr,
    )}`,
  );
}

const providerIds = new Set();
const namespaces = new Set();
const maintainers = new Set();
let externalProviders = 0;
for (const [index, provider] of manifest.providers.entries()) {
  requireExactKeys(provider, [
    "maintainerId",
    "origin",
    "resultSha256",
    "slot",
    "sourceRevision",
  ]);
  const expectedSlot = `provider-${index === 0 ? "a" : "b"}`;
  if (
    provider.slot !== expectedSlot ||
    provider.origin !== (index === 0 ? "in-repository" : "external") ||
    !safeText(provider.maintainerId, 200) ||
    !/^[0-9a-f]{40}$/.test(provider.sourceRevision) ||
    maintainers.has(provider.maintainerId)
  ) {
    throw new Error("memory-provider release provider provenance is invalid");
  }
  maintainers.add(provider.maintainerId);
  if (provider.origin === "external") {
    externalProviders += 1;
  }

  const resultBytes = readBoundedFile(
    join(root, `${expectedSlot}.json`),
    128 * 1024,
    "provider result",
  );
  if (provider.resultSha256 !== sha256(resultBytes)) {
    throw new Error("memory-provider release result digest is invalid");
  }
  const result = parseObject(resultBytes, "provider result");
  verifyConformanceResult(
    result,
    manifest,
    profile,
    providerIds,
    namespaces,
  );
}

if (externalProviders < 1) {
  throw new Error(
    "memory-provider release evidence requires an external provider",
  );
}

const provenanceVerifier = join(
  repositoryRoot,
  "scripts/verify-memory-provider-external-provenance.mjs",
);
const provenanceVerification = spawnSync(
  process.execPath,
  [
    provenanceVerifier,
    join(root, "provider-b.provenance.json"),
    join(root, "provider-b.json"),
    join(root, "provider-b.provenance.json.sig"),
    externalPublicKeyPath,
  ],
  { encoding: "utf8" },
);
if (provenanceVerification.status !== 0) {
  throw new Error(
    `external provider provenance failed verification: ${boundedError(
      provenanceVerification.stderr,
    )}`,
  );
}
const provenance = parseObject(
  externalProvenanceBytes,
  "external provider provenance",
);
const externalProvider = manifest.providers[1];
if (
  provenance.maintainerId !== externalProvider.maintainerId ||
  provenance.sourceRevision !== externalProvider.sourceRevision ||
  provenance.resultSha256 !== externalProvider.resultSha256
) {
  throw new Error("external provider provenance does not match the manifest");
}

process.stdout.write("memory-provider release evidence set verified\n");

function verifyConformanceResult(
  result,
  manifest,
  profile,
  providerIds,
  namespaces,
) {
  requireExactKeys(result, [
    "cases",
    "fixtureId",
    "fixtureSha256",
    "namespace",
    "profileId",
    "profileSha256",
    "protocolVersion",
    "provider",
    "result",
  ]);
  requireExactKeys(result.provider, ["id", "version"]);
  if (
    result.profileId !== profile.profileId ||
    result.profileSha256 !== manifest.profileSha256 ||
    result.fixtureId !== "rembrane.memory-provider.core.lifecycle" ||
    result.fixtureSha256 !== manifest.fixtureSha256 ||
    result.protocolVersion !== manifest.candidateProtocolVersion ||
    result.result !== "pass" ||
    !/^[a-z0-9][a-z0-9._-]+$/.test(result.provider.id) ||
    result.provider.id.length > 255 ||
    !safeText(result.provider.version, 100) ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(result.namespace) ||
    providerIds.has(result.provider.id) ||
    namespaces.has(result.namespace) ||
    !Array.isArray(result.cases) ||
    result.cases.length !== profile.cases.length
  ) {
    throw new Error("memory-provider conformance result is not eligible");
  }
  providerIds.add(result.provider.id);
  namespaces.add(result.namespace);
  for (const [index, resultCase] of result.cases.entries()) {
    requireExactKeys(resultCase, ["id", "result"]);
    if (
      resultCase.id !== profile.cases[index].id ||
      resultCase.result !== "pass"
    ) {
      throw new Error(
        "memory-provider conformance cases are incomplete or reordered",
      );
    }
  }
}

function requireDirectory(path) {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(
      "memory-provider release evidence must be a non-symbolic directory",
    );
  }
}

function requireExactEntries(directory, expected) {
  const actual = readdirSync(directory).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((name, index) => name !== sortedExpected[index])
  ) {
    throw new Error(
      "memory-provider release evidence contains unexpected entries",
    );
  }
}

function readBoundedFile(path, maximum, label) {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > maximum
  ) {
    throw new Error(`memory-provider ${label} must be a bounded regular file`);
  }
  return readFileSync(path);
}

function parseObject(bytes, label) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`memory-provider ${label} must be valid UTF-8 JSON`);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`memory-provider ${label} must be a JSON object`);
  }
  return value;
}

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("memory-provider evidence contains unexpected fields");
  }
}

function safeText(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    /^[ -~]+$/.test(value) &&
    value.trim() === value
  );
}

function canonicalTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  ) {
    return undefined;
  }
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) &&
    new Date(epoch).toISOString().replace(".000Z", "Z") === value
    ? epoch
    : undefined;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function boundedError(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return text.slice(0, 500) || "verification rejected";
}
