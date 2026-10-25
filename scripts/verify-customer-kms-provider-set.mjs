import { lstatSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyCustomerKmsEvidence } from "./customer-kms-evidence.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

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
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const profileBytes = readBoundedRegularFile(
  join(repositoryRoot, "spec/conformance/key-provider-core.json"),
  64 * 1024,
  "customer KMS conformance profile",
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

  const evidencePath = join(directory, "evidence.json");
  const evidence = verifyCustomerKmsEvidence({
    evidenceBytes: readBoundedRegularFile(
      evidencePath,
      64 * 1024,
      "customer KMS evidence",
    ),
    resultBytes: readBoundedRegularFile(
      join(directory, "conformance-result.json"),
      64 * 1024,
      "customer KMS result",
    ),
    policyBytes: readBoundedRegularFile(
      join(directory, "iam-policy.json"),
      1024 * 1024,
      "customer KMS IAM policy",
    ),
    auditBytes: readBoundedRegularFile(
      join(directory, "cloud-audit.json"),
      4 * 1024 * 1024,
      "customer KMS cloud audit evidence",
    ),
    profileBytes,
  });
  if (evidence.cloudProvider !== provider) {
    throw new Error("customer KMS evidence provider does not match its slot");
  }
  if (namespaces.has(evidence.namespace) || providerIds.has(evidence.providerId)) {
    throw new Error("customer KMS evidence set reuses provider identity");
  }
  namespaces.add(evidence.namespace);
  providerIds.add(evidence.providerId);
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
