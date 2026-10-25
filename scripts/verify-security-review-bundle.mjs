import { lstatSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import {
  parseSecurityReviewAttestation,
  parseSecurityReviewManifest,
  sha256,
  verifySecurityReviewRepository,
  verifySecurityReviewSignature,
} from "./security-review-evidence.mjs";

const [bundleInput, publicKeyInput, ...options] = process.argv.slice(2);
const verifyRepository = options.includes("--verify-repository");
const requireApproval = options.includes("--require-approval");
if (
  !bundleInput ||
  !publicKeyInput ||
  options.some(
    (option) =>
      option !== "--verify-repository" && option !== "--require-approval",
  ) ||
  new Set(options).size !== options.length
) {
  throw new Error(
    "usage: verify-security-review-bundle.mjs BUNDLE_DIRECTORY PUBLIC_KEY [--verify-repository] [--require-approval]",
  );
}

const bundle = resolve(process.cwd(), bundleInput);
const metadata = lstatSync(bundle);
if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
  throw new Error("security review bundle must be a non-symbolic directory");
}
const names = [
  "security-review-attestation.json",
  "security-review-attestation.json.sha256",
  "security-review-attestation.json.sig",
  "security-review-manifest.json",
  "security-review-manifest.json.sha256",
  "security-review-manifest.json.sig",
];
const actual = readdirSync(bundle).sort();
if (
  actual.length !== names.length ||
  actual.some((name, index) => name !== names[index])
) {
  throw new Error("security review bundle contains unexpected artifacts");
}

const manifestBytes = read(
  "security-review-manifest.json",
  16 * 1024 * 1024,
);
const manifestChecksumBytes = read(
  "security-review-manifest.json.sha256",
  256,
);
const manifestSignatureBytes = read(
  "security-review-manifest.json.sig",
  64,
);
const attestationBytes = read(
  "security-review-attestation.json",
  64 * 1024,
);
const attestationChecksumBytes = read(
  "security-review-attestation.json.sha256",
  256,
);
const attestationSignatureBytes = read(
  "security-review-attestation.json.sig",
  64,
);
const publicKeyBytes = readBoundedRegularFile(
  publicKeyInput,
  16 * 1024,
  "security review public key",
);

verifyChecksum(
  manifestBytes,
  manifestChecksumBytes,
  "security-review-manifest.json",
);
verifyChecksum(
  attestationBytes,
  attestationChecksumBytes,
  "security-review-attestation.json",
);
verifySecurityReviewSignature(
  manifestBytes,
  manifestSignatureBytes,
  publicKeyBytes,
);
verifySecurityReviewSignature(
  attestationBytes,
  attestationSignatureBytes,
  publicKeyBytes,
);

const manifest = parseSecurityReviewManifest(manifestBytes);
const attestation = parseSecurityReviewAttestation(attestationBytes);
if (
  attestation.manifestSha256 !== sha256(manifestBytes) ||
  attestation.sourceRevision !== manifest.sourceRevision ||
  attestation.scope.manifestFileCount !== manifest.files.length
) {
  throw new Error("security review attestation does not match the manifest");
}
if (
  requireApproval &&
  !["approved", "approved_with_accepted_risks"].includes(
    attestation.disposition,
  )
) {
  throw new Error("security review has not approved the release");
}
if (verifyRepository) {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  verifySecurityReviewRepository(manifest, repositoryRoot);
}

process.stdout.write(`security review bundle verified: ${bundle}\n`);

function read(name, maximum) {
  return readBoundedRegularFile(
    join(bundle, name),
    maximum,
    `security review bundle artifact ${name}`,
  );
}

function verifyChecksum(documentBytes, checksumBytes, name) {
  let record;
  try {
    record = new TextDecoder("utf-8", { fatal: true }).decode(checksumBytes);
  } catch {
    throw new Error(`security review bundle checksum is invalid: ${name}`);
  }
  if (record !== `${sha256(documentBytes)}  ${name}\n`) {
    throw new Error(`security review bundle checksum is invalid: ${name}`);
  }
}
