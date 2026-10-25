import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseProviderRegistry } from "./provider-registry-evidence.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const registryInput =
  process.argv[2] ?? join(repositoryRoot, "spec/provider-registry.json");
if (process.argv.length > 3) {
  throw new Error("usage: verify-provider-registry.mjs [REGISTRY]");
}

const registry = parseProviderRegistry(
  readBoundedRegularFile(
    registryInput,
    4 * 1024 * 1024,
    "provider registry",
  ),
  readBoundedRegularFile(
    join(repositoryRoot, "spec/conformance/semantic-provider-core.json"),
    128 * 1024,
    "semantic provider conformance profile",
  ),
);

let remote;
try {
  remote = execFileSync("git", ["remote", "get-url", "origin"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
} catch {
  remote = "";
}
const canonicalRepository = normalizeRepository(remote);
if (canonicalRepository !== undefined) {
  for (const provider of registry.providers) {
    if (normalizeRepository(provider.source.repository) !== canonicalRepository) {
      continue;
    }
    try {
      execFileSync(
        "git",
        ["cat-file", "-e", `${provider.source.revision}^{commit}`],
        {
          cwd: repositoryRoot,
          stdio: "ignore",
        },
      );
    } catch {
      throw new Error(
        `provider ${provider.id} references an unknown local revision`,
      );
    }
  }
}

process.stdout.write(`provider registry verified: ${resolve(registryInput)}\n`);

function normalizeRepository(value) {
  if (typeof value !== "string" || value.length === 0) return undefined;
  let normalized = value;
  if (normalized.startsWith("git@github.com:")) {
    normalized = `https://github.com/${normalized.slice("git@github.com:".length)}`;
  }
  if (normalized.endsWith(".git")) normalized = normalized.slice(0, -4);
  try {
    const url = new URL(normalized);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== ""
    ) {
      return undefined;
    }
    return url.toString().replace(/\/$/, "");
  } catch {
    return undefined;
  }
}
