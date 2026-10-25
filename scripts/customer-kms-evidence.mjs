import { createHash } from "node:crypto";

export function verifyCustomerKmsEvidence({
  evidenceBytes,
  resultBytes,
  policyBytes,
  auditBytes,
  profileBytes,
  now = Date.now(),
}) {
  const evidence = parseJson(evidenceBytes, "evidence");
  const result = parseJson(resultBytes, "result");
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
  const reviewedAt = canonicalTimestamp(evidence.iamPolicyReview.reviewedAt);
  const completedAt = canonicalTimestamp(evidence.cleanup.completedAt);
  const nowWithSkew = now + 5 * 60 * 1000;
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
    reviewedAt === undefined ||
    completedAt === undefined ||
    executedAt > nowWithSkew ||
    reviewedAt > nowWithSkew ||
    completedAt > nowWithSkew ||
    reviewedAt > completedAt ||
    completedAt < executedAt ||
    !safeText(evidence.iamPolicyReview.reviewerId, 200) ||
    evidence.iamPolicyReview.approved !== true ||
    evidence.cleanup.resourcesDeleted !== true
  ) {
    throw new Error("customer KMS evidence identity or lifecycle is invalid");
  }

  requireJsonDocument(policyBytes, "IAM policy");
  const auditDocument = requireJsonDocument(auditBytes, "cloud audit evidence");
  rejectSensitiveAuditData(auditDocument);
  const profileSha256 = sha256(profileBytes);
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
  return evidence;
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`customer KMS ${label} must be valid UTF-8 JSON`);
  }
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
  const value = parseJson(bytes, label);
  if (value === null || typeof value !== "object") {
    throw new Error(`customer KMS ${label} must contain a JSON object or array`);
  }
  return value;
}

function rejectSensitiveAuditData(value) {
  const sensitiveKey =
    /^(?:access[-_]?key|authorization|client[-_]?secret|credential|password|plaintext|private[-_]?key|secret|session[-_]?key|token|(?:access|refresh|id|session)[-_]?token)$/i;
  const sensitiveValue =
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:^|[^A-Z0-9])AKIA[0-9A-Z]{16}(?:[^A-Z0-9]|$)|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/;
  const pending = [value];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    visited += 1;
    if (visited > 100_000) {
      throw new Error("customer KMS cloud audit evidence is too complex");
    }
    if (Array.isArray(current)) {
      pending.push(...current);
    } else if (current !== null && typeof current === "object") {
      for (const [key, child] of Object.entries(current)) {
        if (sensitiveKey.test(key)) {
          throw new Error(
            "customer KMS cloud audit evidence contains a sensitive field",
          );
        }
        pending.push(child);
      }
    } else if (typeof current === "string" && sensitiveValue.test(current)) {
      throw new Error(
        "customer KMS cloud audit evidence contains credential-like material",
      );
    }
  }
}
