import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const [resultInput, maintainerId, sourceRevision, signedAt] =
  process.argv.slice(2);
if (!resultInput || !maintainerId || !sourceRevision || !signedAt) {
  throw new Error(
    "usage: generate-memory-provider-external-provenance.mjs RESULT MAINTAINER_ID SOURCE_REVISION SIGNED_AT",
  );
}

const resultPath = resolve(process.cwd(), resultInput);
const metadata = lstatSync(resultPath);
if (
  !metadata.isFile() ||
  metadata.isSymbolicLink() ||
  metadata.size === 0 ||
  metadata.size > 128 * 1024
) {
  throw new Error(
    "external provider result must be a bounded regular file",
  );
}
const resultBytes = readFileSync(resultPath);
try {
  const result = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(resultBytes),
  );
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error();
  }
} catch {
  throw new Error("external provider result must be valid UTF-8 JSON");
}

const signedAtEpoch = canonicalTimestamp(signedAt);
if (
  !safeText(maintainerId, 200) ||
  !/^[0-9a-f]{40}$/.test(sourceRevision) ||
  signedAtEpoch === undefined ||
  signedAtEpoch > Date.now() + 5 * 60 * 1000
) {
  throw new Error("external provider provenance identity is invalid");
}

const provenance = {
  schemaVersion: 1,
  maintainerId,
  sourceRevision,
  resultSha256: createHash("sha256").update(resultBytes).digest("hex"),
  signedAt,
};
process.stdout.write(`${JSON.stringify(provenance, null, 2)}\n`);

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
