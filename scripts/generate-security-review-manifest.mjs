import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const allowDirty = process.argv.slice(2).includes("--allow-dirty");
const status = execFileSync("git", ["status", "--porcelain=v1", "-z"], {
  cwd: repositoryRoot,
});
const dirty = status.length !== 0;
if (dirty && !allowDirty) {
  throw new Error(
    "security review manifests require a clean worktree; commit reviewed changes first",
  );
}

const tracked = execFileSync("git", ["ls-files", "-z"], {
  cwd: repositoryRoot,
})
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

const paths = tracked.sort();
if (paths.length === 0) {
  throw new Error("security review inventory is empty");
}

const files = paths.map((path) => {
  const absolutePath = resolve(repositoryRoot, path);
  const repositoryRelative = relative(repositoryRoot, absolutePath);
  if (
    repositoryRelative === ".." ||
    repositoryRelative.startsWith(`..${sep}`) ||
    repositoryRelative.startsWith(sep)
  ) {
    throw new Error(`security review path escapes repository: ${path}`);
  }
  const metadata = lstatSync(absolutePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`security review path is not a regular file: ${path}`);
  }
  const contents = readFileSync(absolutePath);
  return {
    path,
    bytes: contents.length,
    sha256: createHash("sha256").update(contents).digest("hex"),
  };
});
const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: repositoryRoot,
  encoding: "utf8",
}).trim();

process.stdout.write(
  `${JSON.stringify(
    {
      schemaVersion: 1,
      sourceRevision,
      workingTreeDirty: dirty,
      files,
    },
    null,
    2,
  )}\n`,
);
