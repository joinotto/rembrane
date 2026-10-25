import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import {
  parseSecurityReviewAttestation,
  parseSecurityReviewManifest,
  sha256,
} from "./security-review-evidence.mjs";

const [manifestInput, attestationInput] = process.argv.slice(2);
if (
  !manifestInput ||
  !attestationInput ||
  process.argv.length !== 4
) {
  throw new Error(
    "usage: verify-security-review-correlation.mjs MANIFEST ATTESTATION",
  );
}
const manifestBytes = readBoundedRegularFile(
  manifestInput,
  16 * 1024 * 1024,
  "security review manifest",
);
const manifest = parseSecurityReviewManifest(manifestBytes);
const attestation = parseSecurityReviewAttestation(
  readBoundedRegularFile(
    attestationInput,
    64 * 1024,
    "security review attestation",
  ),
);
if (
  attestation.manifestSha256 !== sha256(manifestBytes) ||
  attestation.sourceRevision !== manifest.sourceRevision ||
  attestation.scope.manifestFileCount !== manifest.files.length
) {
  throw new Error("security review attestation does not match the manifest");
}
process.stdout.write("security review correlation verified\n");
