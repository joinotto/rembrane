import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [evidenceInput, resultInput, policyInput, auditInput] =
  process.argv.slice(2);
if (!evidenceInput || !resultInput || !policyInput || !auditInput) {
  throw new Error(
    "usage: verify-customer-kms-evidence.mjs EVIDENCE RESULT IAM_POLICY CLOUD_AUDIT",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const evidence = JSON.parse(
  readBoundedFile(evidenceInput, 64 * 1024, "evidence").toString("utf8"),
);
const resultBytes = readBoundedFile(resultInput, 64 * 1024, "result");
const policyBytes = readBoundedFile(policyInput, 1024 * 1024, "IAM policy");
const auditBytes = readBoundedFile(
  auditInput,
  4 * 1024 * 1024,
  "cloud audit evidence",
);
const profileBytes = readBoundedFile(
  join(repositoryRoot, "spec/conformance/key-provider-core.json"),
  64 * 1024,
  "conformance profile",
);
const result = JSON.parse(resultBytes.toString("utf8"));

requireExactKeys(evidence, [
  "cleanup",
  "cloudProvider",
  "cloudAuditEvidenceSha256",
  "conformanceProfileSha256",
  "conformanceResultSha256",
  "executedAt",
  "iamPolicySha256",
  "iamPolicyReview",
  "namespace",
  "providerId",
  "providerVersion",
  "schemaVersion",
  "sidecarSourceRevision",
]);
requireExactKeys(evidence.iamPolicyReview, [
  "approved",
  "reviewedAt",
  "reviewerId",
]);
requireExactKeys(evidence.cleanup, ["completedAt", "resourcesDeleted"]);

const executedAt = canonicalTimestamp(evidence.executedAt);
const policyReviewedAt = canonicalTimestamp(evidence.iamPolicyReview.reviewedAt);
const completedAt = canonicalTimestamp(evidence.cleanup.completedAt);
const nowWithSkew = Date.now() + 5 * 60 * 1000;
if (
  evidence.schemaVersion !== 1 ||
  !["aws-kms", "azure-key-vault", "google-cloud-kms"].includes(
    evidence.cloudProvider,
  ) ||
  !/^[a-z0-9][a-z0-9._-]+$/.test(evidence.providerId) ||
  evidence.providerId.length > 255 ||
  !safeText(evidence.providerVersion, 100) ||
  !/^[0-9a-f]{40}$/.test(evidence.sidecarSourceRevision) ||
  !/^[A-Za-z0-9._-]{1,80}$/.test(evidence.namespace) ||
  executedAt === undefined ||
  policyReviewedAt === undefined ||
  completedAt === undefined ||
  executedAt > nowWithSkew ||
  policyReviewedAt > nowWithSkew ||
  completedAt > nowWithSkew ||
  policyReviewedAt > completedAt ||
  completedAt < executedAt ||
  !safeText(evidence.iamPolicyReview.reviewerId, 200) ||
  evidence.iamPolicyReview.approved !== true ||
  evidence.cleanup.resourcesDeleted !== true
) {
  throw new Error("customer KMS evidence identity or lifecycle is invalid");
}

const profileSha256 = sha256(profileBytes);
requireJsonDocument(policyBytes, "IAM policy");
requireJsonDocument(auditBytes, "cloud audit evidence");
if (
  evidence.conformanceProfileSha256 !== profileSha256 ||
  evidence.conformanceResultSha256 !== sha256(resultBytes) ||
  evidence.iamPolicySha256 !== sha256(policyBytes) ||
  evidence.cloudAuditEvidenceSha256 !== sha256(auditBytes)
) {
  throw new Error("customer KMS evidence digest binding is invalid");
}

const expectedCases = [
  "authentication",
  "manifest",
  "roundtrip",
  "context-substitution",
  "unknown-key",
  "plaintext-limit",
  "rotation",
  "repeated-rotation",
];
requireExactKeys(result, [
  "cases",
  "namespace",
  "profileId",
  "profileSha256",
  "protocolVersion",
  "providerId",
  "providerVersion",
  "result",
]);
if (
  result.profileId !== "rembrane.key-provider.core" ||
  result.profileSha256 !== profileSha256 ||
  result.protocolVersion !== "0.1" ||
  result.providerId !== evidence.providerId ||
  result.providerVersion !== evidence.providerVersion ||
  result.namespace !== evidence.namespace ||
  result.result !== "pass" ||
  !Array.isArray(result.cases) ||
  result.cases.length !== expectedCases.length ||
  result.cases.some((item, index) => {
    requireExactKeys(item, ["id", "result"]);
    return item.id !== expectedCases[index] || item.result !== "pass";
  })
) {
  throw new Error("customer KMS conformance result is not eligible");
}

process.stdout.write("customer KMS conformance evidence verified\n");

function readBoundedFile(input, maximum, label) {
  const path = resolve(process.cwd(), input);
  const metadata = lstatSync(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size === 0 ||
    metadata.size > maximum
  ) {
    throw new Error(`customer KMS ${label} must be a bounded regular file`);
  }
  return readFileSync(path);
}

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("customer KMS evidence contains unexpected fields");
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

function requireJsonDocument(bytes, label) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`customer KMS ${label} must be valid UTF-8 JSON`);
  }
  if (value === null || typeof value !== "object") {
    throw new Error(`customer KMS ${label} must contain a JSON object or array`);
  }
}
