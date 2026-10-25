import { createHash, createPublicKey, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { relative, resolve, sep } from "node:path";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const safeTextPattern = /^[ -~]+$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const revisionPattern = /^[0-9a-f]{40}$/;
const safePathPattern = /^[A-Za-z0-9._@+/-]+$/;
const findingLevels = [
  "critical",
  "high",
  "moderate",
  "low",
  "informational",
  "unresolved",
];

export function parseSecurityReviewManifest(bytes) {
  const manifest = parseJson(bytes, "security review manifest");
  if (
    manifest === null ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    Object.keys(manifest).sort().join(",") !==
      "files,schemaVersion,sourceRevision,workingTreeDirty" ||
    manifest.schemaVersion !== 1 ||
    !revisionPattern.test(manifest.sourceRevision) ||
    typeof manifest.workingTreeDirty !== "boolean" ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0 ||
    manifest.files.length > 10_000
  ) {
    throw new Error("security review manifest structure is invalid");
  }
  let previousPath;
  for (const entry of manifest.files) {
    if (
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      Object.keys(entry).sort().join(",") !== "bytes,path,sha256" ||
      !safePath(entry.path) ||
      !Number.isSafeInteger(entry.bytes) ||
      entry.bytes < 0 ||
      !sha256Pattern.test(entry.sha256) ||
      (previousPath !== undefined && entry.path <= previousPath)
    ) {
      throw new Error("security review manifest file inventory is invalid");
    }
    previousPath = entry.path;
  }
  return manifest;
}

export function verifySecurityReviewRepository(manifest, repositoryRoot) {
  if (manifest.workingTreeDirty) {
    throw new Error("security review evidence cannot describe a dirty worktree");
  }
  const status = execFileSync("git", ["status", "--porcelain=v1", "-z"], {
    cwd: repositoryRoot,
  });
  if (status.length !== 0) {
    throw new Error("security review repository must be clean");
  }
  const revision = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repositoryRoot,
    encoding: "utf8",
  }).trim();
  if (manifest.sourceRevision !== revision) {
    throw new Error(
      "security review manifest revision does not match the repository",
    );
  }
  const tracked = decodeTrackedPaths(
    execFileSync("git", ["ls-files", "-z"], { cwd: repositoryRoot }),
  ).sort();
  if (
    tracked.length !== manifest.files.length ||
    tracked.some((path, index) => path !== manifest.files[index].path)
  ) {
    throw new Error(
      "security review manifest inventory does not match tracked files",
    );
  }
  for (const entry of manifest.files) {
    const absolutePath = resolveReviewPath(repositoryRoot, entry.path);
    const contents = readBoundedRegularFile(
      absolutePath,
      Number.MAX_SAFE_INTEGER,
      `security review path ${entry.path}`,
      { allowEmpty: true },
    );
    if (
      entry.bytes !== contents.length ||
      entry.sha256 !== sha256(contents)
    ) {
      throw new Error(`security review file evidence differs: ${entry.path}`);
    }
  }
}

export function parseSecurityReviewAttestation(bytes, now = Date.now()) {
  const value = parseJson(bytes, "security review attestation");
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
  if (value?.reportReference !== undefined) {
    attestationKeys.push("reportReference");
  }
  requireExactKeys(value, attestationKeys);
  const reviewedAt = canonicalTimestamp(value.reviewedAt);
  if (
    value.schemaVersion !== 1 ||
    !revisionPattern.test(value.sourceRevision) ||
    !sha256Pattern.test(value.manifestSha256) ||
    reviewedAt === undefined ||
    reviewedAt > now + 5 * 60 * 1_000 ||
    !new Set([
      "approved",
      "approved_with_accepted_risks",
      "changes_required",
    ]).has(value.disposition) ||
    !optionalSafeText(value.reportReference, 500)
  ) {
    throw new Error("security review attestation identity is invalid");
  }
  const reviewerKeys = ["id", "independent"];
  if (value.reviewer?.organization !== undefined) {
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
  requireExactKeys(value.findings, findingLevels);
  if (
    findingLevels.some(
      (level) =>
        !Number.isSafeInteger(value.findings[level]) ||
        value.findings[level] < 0 ||
        value.findings[level] > 1_000_000,
    ) ||
    (value.disposition === "approved" &&
      (value.findings.unresolved !== 0 ||
        value.scope.exclusions.length !== 0)) ||
    (value.disposition === "approved_with_accepted_risks" &&
      (value.findings.unresolved !== 0 ||
        value.reportReference === undefined ||
        (value.findings.critical === 0 &&
          value.findings.high === 0 &&
          value.findings.moderate === 0 &&
          value.findings.low === 0 &&
          value.scope.exclusions.length === 0))) ||
    (value.disposition === "changes_required" &&
      value.findings.unresolved === 0)
  ) {
    throw new Error("security review attestation findings are inconsistent");
  }
  return value;
}

export function verifySecurityReviewSignature(
  documentBytes,
  signatureBytes,
  publicKeyBytes,
) {
  let valid = false;
  try {
    const publicKey = createPublicKey(publicKeyBytes);
    valid =
      publicKey.asymmetricKeyType === "ed25519" &&
      signatureBytes.length === 64 &&
      verify(null, documentBytes, publicKey, signatureBytes);
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("security review signature is invalid");
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`${label} must be valid UTF-8 JSON`);
  }
}

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("security review evidence has unexpected fields");
  }
}

function safeText(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    safeTextPattern.test(value) &&
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
    return undefined;
  }
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) &&
    new Date(epoch).toISOString().replace(".000Z", "Z") === value
    ? epoch
    : undefined;
}

function safePath(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    Buffer.byteLength(path) > 4_096 ||
    !safePathPattern.test(path)
  ) {
    return false;
  }
  return !path
    .split("/")
    .some(
      (component) =>
        component.length === 0 || component === "." || component === "..",
    );
}

function decodeTrackedPaths(bytes) {
  return new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .split("\0")
    .filter(Boolean);
}

function resolveReviewPath(root, path) {
  if (!safePath(path)) {
    throw new Error(`security review path is ambiguous or unsafe: ${path}`);
  }
  const absolutePath = resolve(root, path);
  const repositoryRelative = relative(root, absolutePath);
  if (
    repositoryRelative === ".." ||
    repositoryRelative.startsWith(`..${sep}`) ||
    repositoryRelative.startsWith(sep)
  ) {
    throw new Error(`security review path escapes repository: ${path}`);
  }
  return absolutePath;
}
