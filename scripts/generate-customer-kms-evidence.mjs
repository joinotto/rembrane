import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [
  cloudProvider,
  sourceRevision,
  resultInput,
  policyInput,
  auditInput,
  reviewerId,
  executedAt,
  policyReviewedAt,
  cleanupCompletedAt,
] = process.argv.slice(2);

if (
  !cloudProvider ||
  !sourceRevision ||
  !resultInput ||
  !policyInput ||
  !auditInput ||
  !reviewerId ||
  !executedAt ||
  !policyReviewedAt ||
  !cleanupCompletedAt
) {
  throw new Error(
    "usage: generate-customer-kms-evidence.mjs CLOUD_PROVIDER SOURCE_REVISION RESULT IAM_POLICY CLOUD_AUDIT REVIEWER_ID EXECUTED_AT POLICY_REVIEWED_AT CLEANUP_COMPLETED_AT",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
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
const result = JSON.parse(
  new TextDecoder("utf-8", { fatal: true }).decode(resultBytes),
);

if (
  !["aws-kms", "azure-key-vault", "google-cloud-kms"].includes(cloudProvider) ||
  !/^[0-9a-f]{40}$/.test(sourceRevision) ||
  !safeText(reviewerId, 200)
) {
  throw new Error("customer KMS evidence generation metadata is invalid");
}
for (const timestamp of [executedAt, policyReviewedAt, cleanupCompletedAt]) {
  if (!canonicalTimestamp(timestamp)) {
    throw new Error("customer KMS evidence generation timestamp is invalid");
  }
}
if (
  result === null ||
  typeof result !== "object" ||
  Array.isArray(result) ||
  typeof result.providerId !== "string" ||
  typeof result.providerVersion !== "string" ||
  typeof result.namespace !== "string"
) {
  throw new Error("customer KMS conformance result identity is invalid");
}

const evidence = {
  schemaVersion: 1,
  cloudProvider,
  providerId: result.providerId,
  providerVersion: result.providerVersion,
  sidecarSourceRevision: sourceRevision,
  namespace: result.namespace,
  executedAt,
  conformanceProfileSha256: sha256(profileBytes),
  conformanceResultSha256: sha256(resultBytes),
  iamPolicySha256: sha256(policyBytes),
  iamPolicyReview: {
    reviewerId,
    reviewedAt: policyReviewedAt,
    approved: true,
  },
  cloudAuditEvidenceSha256: sha256(auditBytes),
  cleanup: {
    completedAt: cleanupCompletedAt,
    resourcesDeleted: true,
  },
};

process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);

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

function safeText(value, maximum) {
  return (
    value.length <= maximum &&
    /^[ -~]+$/.test(value) &&
    value.trim() === value
  );
}

function canonicalTimestamp(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    return false;
  }
  const epoch = Date.parse(value);
  return (
    Number.isFinite(epoch) &&
    new Date(epoch).toISOString().replace(".000Z", "Z") === value
  );
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
