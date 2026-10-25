import { spawnSync } from "node:child_process";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const input = process.argv[2];
if (!input) {
  throw new Error(
    "usage: verify-customer-kms-provider-set.mjs EVIDENCE_DIRECTORY",
  );
}

const root = resolve(process.cwd(), input);
const rootMetadata = lstatSync(root);
if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
  throw new Error("customer KMS evidence set must be a non-symbolic directory");
}

const providers = ["aws-kms", "azure-key-vault", "google-cloud-kms"];
requireExactEntries(root, providers);
const verifier = join(
  dirname(fileURLToPath(import.meta.url)),
  "verify-customer-kms-evidence.mjs",
);
const namespaces = new Set();
const providerIds = new Set();

for (const provider of providers) {
  const directory = join(root, provider);
  const metadata = lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("customer KMS provider evidence must be a directory");
  }
  const files = [
    "cloud-audit.json",
    "conformance-result.json",
    "evidence.json",
    "iam-policy.json",
  ];
  requireExactEntries(directory, files);
  for (const name of files) {
    const fileMetadata = lstatSync(join(directory, name));
    if (!fileMetadata.isFile() || fileMetadata.isSymbolicLink()) {
      throw new Error("customer KMS provider evidence must use regular files");
    }
  }

  const evidence = JSON.parse(
    readFileSync(join(directory, "evidence.json"), "utf8"),
  );
  if (evidence.cloudProvider !== provider) {
    throw new Error("customer KMS evidence provider does not match its slot");
  }
  if (namespaces.has(evidence.namespace) || providerIds.has(evidence.providerId)) {
    throw new Error("customer KMS evidence set reuses provider identity");
  }
  namespaces.add(evidence.namespace);
  providerIds.add(evidence.providerId);

  const verification = spawnSync(
    process.execPath,
    [
      verifier,
      join(directory, "evidence.json"),
      join(directory, "conformance-result.json"),
      join(directory, "iam-policy.json"),
      join(directory, "cloud-audit.json"),
    ],
    { encoding: "utf8" },
  );
  if (verification.status !== 0) {
    throw new Error(
      `customer KMS ${provider} evidence failed verification: ${boundedError(
        verification.stderr,
      )}`,
    );
  }
}

process.stdout.write("customer KMS provider evidence set verified\n");

function requireExactEntries(directory, expected) {
  const actual = readdirSync(directory).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((name, index) => name !== sortedExpected[index])
  ) {
    throw new Error("customer KMS evidence set contains unexpected entries");
  }
}

function boundedError(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return text.slice(0, 500) || "verification rejected";
}
