import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const [provenanceInput, resultInput, signatureInput, publicKeyInput] =
  process.argv.slice(2);
if (!provenanceInput || !resultInput || !signatureInput || !publicKeyInput) {
  throw new Error(
    "usage: verify-memory-provider-external-provenance.mjs PROVENANCE RESULT SIGNATURE PUBLIC_KEY",
  );
}

const provenancePath = resolve(process.cwd(), provenanceInput);
const resultPath = resolve(process.cwd(), resultInput);
const signaturePath = resolve(process.cwd(), signatureInput);
const publicKeyPath = resolve(process.cwd(), publicKeyInput);
const provenanceBytes = readBounded(provenancePath, 16 * 1024, "provenance");
const resultBytes = readBounded(resultPath, 128 * 1024, "result");
readBounded(signaturePath, 64, "signature");
readBounded(publicKeyPath, 16 * 1024, "public key");
const provenance = JSON.parse(
  new TextDecoder("utf-8", { fatal: true }).decode(provenanceBytes),
);

if (
  provenance === null ||
  typeof provenance !== "object" ||
  Array.isArray(provenance) ||
  Object.keys(provenance).sort().join(",") !==
    [
      "maintainerId",
      "resultSha256",
      "schemaVersion",
      "signedAt",
      "sourceRevision",
    ]
      .sort()
      .join(",") ||
  provenance.schemaVersion !== 1 ||
  !safeText(provenance.maintainerId, 200) ||
  !/^[0-9a-f]{40}$/.test(provenance.sourceRevision) ||
  provenance.resultSha256 !== sha256(resultBytes) ||
  canonicalTimestamp(provenance.signedAt) === undefined ||
  canonicalTimestamp(provenance.signedAt) > Date.now() + 5 * 60 * 1000
) {
  throw new Error("external provider provenance is invalid");
}

const verification = spawnSync(
  "openssl",
  [
    "pkeyutl",
    "-verify",
    "-pubin",
    "-inkey",
    publicKeyPath,
    "-rawin",
    "-in",
    provenancePath,
    "-sigfile",
    signaturePath,
  ],
  { encoding: "utf8" },
);
if (verification.status !== 0) {
  throw new Error("external provider provenance signature is invalid");
}

process.stdout.write("external memory-provider provenance verified\n");

function readBounded(path, maximum, label) {
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > maximum
  ) {
    throw new Error(`external provider ${label} must be a bounded regular file`);
  }
  return readFileSync(path);
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
