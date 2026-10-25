import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import { parseSecurityReviewAttestation } from "./security-review-evidence.mjs";

const input = process.argv[2];
if (!input) {
  throw new Error(
    "usage: verify-security-review-attestation.mjs ATTESTATION",
  );
}
parseSecurityReviewAttestation(
  readBoundedRegularFile(
    input,
    64 * 1024,
    "security review attestation",
  ),
);
process.stdout.write("security review attestation verified\n");
