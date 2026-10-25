import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyCustomerKmsEvidence } from "./customer-kms-evidence.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const [evidenceInput, resultInput, policyInput, auditInput] =
  process.argv.slice(2);
if (!evidenceInput || !resultInput || !policyInput || !auditInput) {
  throw new Error(
    "usage: verify-customer-kms-evidence.mjs EVIDENCE RESULT IAM_POLICY CLOUD_AUDIT",
  );
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
verifyCustomerKmsEvidence({
  evidenceBytes: readBoundedRegularFile(
    evidenceInput,
    64 * 1024,
    "customer KMS evidence",
  ),
  resultBytes: readBoundedRegularFile(
    resultInput,
    64 * 1024,
    "customer KMS result",
  ),
  policyBytes: readBoundedRegularFile(
    policyInput,
    1024 * 1024,
    "customer KMS IAM policy",
  ),
  auditBytes: readBoundedRegularFile(
    auditInput,
    4 * 1024 * 1024,
    "customer KMS cloud audit evidence",
  ),
  profileBytes: readBoundedRegularFile(
    join(repositoryRoot, "spec/conformance/key-provider-core.json"),
    64 * 1024,
    "customer KMS conformance profile",
  ),
});

process.stdout.write("customer KMS conformance evidence verified\n");
