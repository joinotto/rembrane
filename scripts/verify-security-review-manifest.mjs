import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_REVIEW_FILES = 10_000;
const MAX_PATH_BYTES = 4_096;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REVISION_PATTERN = /^[0-9a-f]{40}$/;
const SAFE_PATH_PATTERN = /^[A-Za-z0-9._@+/-]+$/;

const manifestArgument = process.argv[2];
if (!manifestArgument) {
  throw new Error(
    "usage: verify-security-review-manifest.mjs MANIFEST [--verify-repository]",
  );
}
const verifyRepository = process.argv.slice(3).includes("--verify-repository");
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(process.cwd(), manifestArgument);
const manifestMetadata = lstatSync(manifestPath);
if (!manifestMetadata.isFile() || manifestMetadata.isSymbolicLink()) {
  throw new Error("security review manifest must be a regular non-symbolic file");
}
if (manifestMetadata.size === 0 || manifestMetadata.size > MAX_MANIFEST_BYTES) {
  throw new Error("security review manifest exceeds the bounded size");
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
if (
  manifest === null ||
  typeof manifest !== "object" ||
  Array.isArray(manifest) ||
  manifest.schemaVersion !== 1 ||
  !REVISION_PATTERN.test(manifest.sourceRevision) ||
  typeof manifest.workingTreeDirty !== "boolean" ||
  !Array.isArray(manifest.files) ||
  manifest.files.length === 0 ||
  manifest.files.length > MAX_REVIEW_FILES
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
    typeof entry.sha256 !== "string" ||
    !SHA256_PATTERN.test(entry.sha256) ||
    (previousPath !== undefined && entry.path <= previousPath)
  ) {
    throw new Error("security review manifest file inventory is invalid");
  }
  previousPath = entry.path;
}

if (verifyRepository) {
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
    throw new Error("security review manifest revision does not match the repository");
  }
  const tracked = decodeTrackedPaths(
    execFileSync("git", ["ls-files", "-z"], { cwd: repositoryRoot }),
  ).sort();
  if (
    tracked.length !== manifest.files.length ||
    tracked.some((path, index) => path !== manifest.files[index].path)
  ) {
    throw new Error("security review manifest inventory does not match tracked files");
  }
  for (const entry of manifest.files) {
    const absolutePath = resolveReviewPath(repositoryRoot, entry.path);
    const metadata = lstatSync(absolutePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`security review path is not a regular file: ${entry.path}`);
    }
    const contents = readFileSync(absolutePath);
    const digest = createHash("sha256").update(contents).digest("hex");
    if (entry.bytes !== contents.length || entry.sha256 !== digest) {
      throw new Error(`security review file evidence differs: ${entry.path}`);
    }
  }
}

process.stdout.write(
  `security review manifest verified (${manifest.files.length} files)\n`,
);

function safePath(path) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    Buffer.byteLength(path) > MAX_PATH_BYTES ||
    !SAFE_PATH_PATTERN.test(path)
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
