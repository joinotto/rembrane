import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const MAX_ATTESTATION_BYTES = 64 * 1024;
const SAFE_TEXT = /^[ -~]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REVISION = /^[0-9a-f]{40}$/;
const DISPOSITIONS = new Set([
  "approved",
  "approved_with_accepted_risks",
  "changes_required",
]);
const FINDING_LEVELS = [
  "critical",
  "high",
  "moderate",
  "low",
  "informational",
  "unresolved",
];

const input = process.argv[2];
if (!input) {
  throw new Error(
    "usage: verify-security-review-attestation.mjs ATTESTATION",
  );
}
const path = resolve(process.cwd(), input);
const metadata = lstatSync(path);
if (!metadata.isFile() || metadata.isSymbolicLink()) {
  throw new Error("security review attestation must be a regular file");
}
if (metadata.size === 0 || metadata.size > MAX_ATTESTATION_BYTES) {
  throw new Error("security review attestation exceeds the bounded size");
}

const value = JSON.parse(readFileSync(path, "utf8"));
const attestationKeys = [
  "disposition",
  "findings",
  "manifestSha256",
  "reviewedAt",
  "reviewer",
  "schemaVersion",
  "scope",
  "sourceRevision",
];
if (value.reportReference !== undefined) {
  attestationKeys.push("reportReference");
}
requireExactKeys(value, attestationKeys);
if (
  value.schemaVersion !== 1 ||
  !REVISION.test(value.sourceRevision) ||
  !SHA256.test(value.manifestSha256) ||
  !canonicalTimestamp(value.reviewedAt) ||
  !DISPOSITIONS.has(value.disposition) ||
  !optionalSafeText(value.reportReference, 500)
) {
  throw new Error("security review attestation identity is invalid");
}

const reviewerKeys = ["id", "independent"];
if (value.reviewer.organization !== undefined) {
  reviewerKeys.push("organization");
}
requireExactKeys(value.reviewer, reviewerKeys);
if (
  value.reviewer.independent !== true ||
  !safeText(value.reviewer.id, 200) ||
  !optionalSafeText(value.reviewer.organization, 200)
) {
  throw new Error("security review attestation reviewer is invalid");
}

requireExactKeys(value.scope, ["exclusions", "manifestFileCount"]);
if (
  !Number.isSafeInteger(value.scope.manifestFileCount) ||
  value.scope.manifestFileCount < 1 ||
  value.scope.manifestFileCount > 10_000 ||
  !Array.isArray(value.scope.exclusions) ||
  value.scope.exclusions.length > 100 ||
  value.scope.exclusions.some((item) => !safeText(item, 500)) ||
  new Set(value.scope.exclusions).size !== value.scope.exclusions.length
) {
  throw new Error("security review attestation scope is invalid");
}

requireExactKeys(value.findings, FINDING_LEVELS);
if (
  FINDING_LEVELS.some(
    (level) =>
      !Number.isSafeInteger(value.findings[level]) ||
      value.findings[level] < 0 ||
      value.findings[level] > 1_000_000,
  ) ||
  (value.disposition === "approved" &&
    (value.findings.unresolved !== 0 || value.scope.exclusions.length !== 0)) ||
  (value.disposition === "approved_with_accepted_risks" &&
    value.findings.unresolved !== 0) ||
  (value.disposition === "changes_required" &&
    value.findings.unresolved === 0)
) {
  throw new Error("security review attestation findings are inconsistent");
}

process.stdout.write("security review attestation verified\n");

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("security review attestation has unexpected fields");
  }
}

function safeText(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    SAFE_TEXT.test(value) &&
    value.trim() === value
  );
}

function optionalSafeText(value, maximum) {
  return value === undefined || safeText(value, maximum);
}

function canonicalTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  ) {
    return false;
  }
  const epoch = Date.parse(value);
  return (
    Number.isFinite(epoch) &&
    new Date(epoch).toISOString().replace(".000Z", "Z") === value
  );
}
