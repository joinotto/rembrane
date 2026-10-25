import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, relative, resolve, sep } from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

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

const tracked = new TextDecoder("utf-8", { fatal: true })
  .decode(
    execFileSync("git", ["ls-files", "-z"], {
      cwd: repositoryRoot,
    }),
  )
  .split("\0")
  .filter(Boolean);

const paths = tracked.sort();
if (paths.length === 0) {
  throw new Error("security review inventory is empty");
}

const files = paths.map((path) => {
  const components = path.split("/");
  if (
    path.length > 4_096 ||
    !/^[A-Za-z0-9._@+/-]+$/.test(path) ||
    components.some(
      (component) =>
        component.length === 0 || component === "." || component === "..",
    )
  ) {
    throw new Error(`security review path is ambiguous or unsafe: ${path}`);
  }
  const absolutePath = resolve(repositoryRoot, path);
  const repositoryRelative = relative(repositoryRoot, absolutePath);
  if (
    repositoryRelative === ".." ||
    repositoryRelative.startsWith(`..${sep}`) ||
    repositoryRelative.startsWith(sep)
  ) {
    throw new Error(`security review path escapes repository: ${path}`);
  }
  const contents = readBoundedRegularFile(
    absolutePath,
    Number.MAX_SAFE_INTEGER,
    `security review path ${path}`,
    { allowEmpty: true },
  );
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
