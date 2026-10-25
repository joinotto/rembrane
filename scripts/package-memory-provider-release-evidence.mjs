import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  constants,
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [
  outputInput,
  sourceRevision,
  generatedAt,
  mixedInput,
  providerAInput,
  providerAOrigin,
  providerAMaintainer,
  providerASourceRevision,
  providerBInput,
  providerBOrigin,
  providerBMaintainer,
  providerBSourceRevision,
  providerBSignatureInput,
  externalPublicKeyInput,
] = process.argv.slice(2);
if (
  !outputInput ||
  !sourceRevision ||
  !generatedAt ||
  !mixedInput ||
  !providerAInput ||
  !providerAOrigin ||
  !providerAMaintainer ||
  !providerASourceRevision ||
  !providerBInput ||
  !providerBOrigin ||
  !providerBMaintainer ||
  !providerBSourceRevision ||
  !providerBSignatureInput ||
  !externalPublicKeyInput
) {
  throw new Error(
    "usage: package-memory-provider-release-evidence.mjs OUTPUT SOURCE_REVISION GENERATED_AT MIXED_VERSION PROVIDER_A_RESULT PROVIDER_A_ORIGIN PROVIDER_A_MAINTAINER PROVIDER_A_REVISION PROVIDER_B_RESULT external PROVIDER_B_MAINTAINER PROVIDER_B_REVISION PROVIDER_B_SIGNATURE EXTERNAL_PUBLIC_KEY",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const output = resolve(process.cwd(), outputInput);
const mixed = readBoundedFile(mixedInput, 128 * 1024, "mixed-version evidence");
const providerA = readBoundedFile(
  providerAInput,
  128 * 1024,
  "provider-a result",
);
const providerB = readBoundedFile(
  providerBInput,
  128 * 1024,
  "provider-b result",
);
const providerBSignature = readBoundedFile(
  providerBSignatureInput,
  64,
  "provider-b signature",
);
const externalPublicKey = readBoundedFile(
  externalPublicKeyInput,
  16 * 1024,
  "external public key",
);
const lockPath = join(
  repositoryRoot,
  "spec/memory-provider-compatibility-lock.json",
);
const migrationPath = join(
  repositoryRoot,
  "spec/MEMORY_PROVIDER_0.1_TO_1.0_MIGRATION.md",
);
const profilePath = join(
  repositoryRoot,
  "spec/conformance/memory-provider-core.json",
);
const fixturePath = join(
  repositoryRoot,
  "spec/conformance/memory-provider-core-fixtures.json",
);
const lock = readBoundedFile(lockPath, 128 * 1024, "compatibility lock");
const migration = readBoundedFile(migrationPath, 256 * 1024, "migration notes");
const profile = readBoundedFile(profilePath, 128 * 1024, "profile");
const fixture = readBoundedFile(fixturePath, 256 * 1024, "fixtures");
const lockDocument = parseObject(lock, "compatibility lock");

if (
  !/^[0-9a-f]{40}$/.test(sourceRevision) ||
  canonicalTimestamp(generatedAt) === undefined ||
  canonicalTimestamp(generatedAt) > Date.now() + 5 * 60 * 1000
) {
  throw new Error("memory-provider release identity is invalid");
}
for (const [origin, maintainer, revision] of [
  [providerAOrigin, providerAMaintainer, providerASourceRevision],
  [providerBOrigin, providerBMaintainer, providerBSourceRevision],
]) {
  if (
    !["in-repository", "external"].includes(origin) ||
    !safeText(maintainer, 200) ||
    !/^[0-9a-f]{40}$/.test(revision)
  ) {
    throw new Error("memory-provider provider provenance is invalid");
  }
}
if (
  providerAMaintainer === providerBMaintainer ||
  ![providerAOrigin, providerBOrigin].includes("external")
) {
  throw new Error(
    "memory-provider release requires distinct maintainers and an external provider",
  );
}

const manifest = {
  schemaVersion: 1,
  candidateProtocolVersion: lockDocument.protocolVersion,
  candidateSourceRevision: sourceRevision,
  generatedAt,
  profileSha256: sha256(profile),
  fixtureSha256: sha256(fixture),
  compatibilityLockSha256: sha256(lock),
  migrationNotesSha256: sha256(migration),
  mixedVersionEvidenceSha256: sha256(mixed),
  externalResultSignatureSha256: sha256(providerBSignature),
  externalPublicKeySha256: sha256(externalPublicKey),
  providers: [
    {
      slot: "provider-a",
      origin: providerAOrigin,
      maintainerId: providerAMaintainer,
      sourceRevision: providerASourceRevision,
      resultSha256: sha256(providerA),
    },
    {
      slot: "provider-b",
      origin: providerBOrigin,
      maintainerId: providerBMaintainer,
      sourceRevision: providerBSourceRevision,
      resultSha256: sha256(providerB),
    },
  ],
};

let created = false;
try {
  mkdirSync(output, { mode: 0o700 });
  created = true;
  copyExclusive(lockPath, join(output, "compatibility-lock.json"));
  copyExclusive(migrationPath, join(output, "migration.md"));
  copyBytes(mixed, join(output, "mixed-version.json"));
  copyBytes(providerA, join(output, "provider-a.json"));
  copyBytes(providerB, join(output, "provider-b.json"));
  copyBytes(providerBSignature, join(output, "provider-b.json.sig"));
  writeFileSync(
    join(output, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );

  const verification = spawnSync(
    process.execPath,
    [
      join(
        repositoryRoot,
        "scripts/verify-memory-provider-release-evidence.mjs",
      ),
      output,
      resolve(process.cwd(), externalPublicKeyInput),
    ],
    { encoding: "utf8" },
  );
  if (verification.status !== 0) {
    throw new Error(
      `packaged memory-provider evidence failed verification: ${boundedError(
        verification.stderr,
      )}`,
    );
  }
} catch (error) {
  if (created) {
    rmSync(output, { recursive: true, force: true });
  }
  throw error;
}

process.stdout.write(`${output}\n`);

function readBoundedFile(input, maximum, label) {
  const path = resolve(process.cwd(), input);
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

function copyExclusive(source, destination) {
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  chmodSync(destination, 0o600);
}

function copyBytes(bytes, destination) {
  writeFileSync(destination, bytes, { flag: "wx", mode: 0o600 });
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
