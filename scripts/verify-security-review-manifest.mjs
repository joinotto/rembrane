import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import {
  parseSecurityReviewManifest,
  verifySecurityReviewRepository,
} from "./security-review-evidence.mjs";

const input = process.argv[2];
const options = process.argv.slice(3);
if (
  !input ||
  options.some((option) => option !== "--verify-repository") ||
  options.filter((option) => option === "--verify-repository").length > 1
) {
  throw new Error(
    "usage: verify-security-review-manifest.mjs MANIFEST [--verify-repository]",
  );
}
const manifest = parseSecurityReviewManifest(
  readBoundedRegularFile(
    input,
    16 * 1024 * 1024,
    "security review manifest",
  ),
);
if (options.includes("--verify-repository")) {
  verifySecurityReviewRepository(
    manifest,
    resolve(dirname(fileURLToPath(import.meta.url)), ".."),
  );
}
process.stdout.write(
  `security review manifest verified (${manifest.files.length} files)\n`,
);
