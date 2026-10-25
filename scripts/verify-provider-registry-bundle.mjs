import { lstatSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseProviderRegistry, sha256 } from "./provider-registry-evidence.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import { verifySecurityReviewSignature } from "./security-review-evidence.mjs";

const [bundleInput, publicKeyInput] = process.argv.slice(2);
if (!bundleInput || !publicKeyInput || process.argv.length !== 4) {
  throw new Error(
    "usage: verify-provider-registry-bundle.mjs BUNDLE_DIRECTORY PUBLIC_KEY",
  );
}
const bundle = resolve(process.cwd(), bundleInput);
const metadata = lstatSync(bundle);
if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
  throw new Error("provider registry bundle must be a non-symbolic directory");
}
const expected = [
  "provider-registry.json",
  "provider-registry.json.sha256",
  "provider-registry.json.sig",
];
const actual = readdirSync(bundle).sort();
if (
  actual.length !== expected.length ||
  actual.some((name, index) => name !== expected[index])
) {
  throw new Error("provider registry bundle contains unexpected artifacts");
}

const registryBytes = read(
  "provider-registry.json",
  4 * 1024 * 1024,
);
const checksumBytes = read("provider-registry.json.sha256", 256);
const signatureBytes = read("provider-registry.json.sig", 64);
const publicKeyBytes = readBoundedRegularFile(
  publicKeyInput,
  16 * 1024,
  "provider registry public key",
);
const checksum = new TextDecoder("utf-8", { fatal: true }).decode(checksumBytes);
if (
  checksum !==
  `${sha256(registryBytes)}  provider-registry.json\n`
) {
  throw new Error("provider registry bundle checksum is invalid");
}
verifySecurityReviewSignature(registryBytes, signatureBytes, publicKeyBytes);

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
parseProviderRegistry(
  registryBytes,
  readBoundedRegularFile(
    join(repositoryRoot, "spec/conformance/semantic-provider-core.json"),
    128 * 1024,
    "semantic provider conformance profile",
  ),
);

process.stdout.write(`provider registry bundle verified: ${bundle}\n`);

function read(name, maximum) {
  return readBoundedRegularFile(
    join(bundle, name),
    maximum,
    `provider registry bundle artifact ${name}`,
  );
}
