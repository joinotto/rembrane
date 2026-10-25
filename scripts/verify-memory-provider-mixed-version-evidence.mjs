import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyMemoryProviderMixedVersionEvidence } from "./memory-provider-mixed-version-evidence.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const [evidenceInput] = process.argv.slice(2);
if (!evidenceInput) {
  throw new Error(
    "usage: verify-memory-provider-mixed-version-evidence.mjs EVIDENCE",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
verifyMemoryProviderMixedVersionEvidence({
  evidenceBytes: readBoundedRegularFile(
    evidenceInput,
    128 * 1024,
    "memory-provider evidence",
  ),
  profileBytes: readBoundedRegularFile(
    join(repositoryRoot, "spec/conformance/memory-provider-core.json"),
    128 * 1024,
    "canonical memory-provider profile",
  ),
  fixtureBytes: readBoundedRegularFile(
    join(
      repositoryRoot,
      "spec/conformance/memory-provider-core-fixtures.json",
    ),
    256 * 1024,
    "canonical memory-provider fixtures",
  ),
});

process.stdout.write("memory-provider mixed-version evidence verified\n");
