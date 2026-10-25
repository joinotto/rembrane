import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import { verifySecurityReviewSignature } from "./security-review-evidence.mjs";

const [registryInput, signatureInput, publicKeyInput] = process.argv.slice(2);
if (!registryInput || !signatureInput || !publicKeyInput) {
  throw new Error(
    "usage: verify-provider-registry-signature.mjs REGISTRY SIGNATURE PUBLIC_KEY",
  );
}

const registryBytes = readBoundedRegularFile(
  registryInput,
  4 * 1024 * 1024,
  "provider registry",
);
const signatureBytes = readBoundedRegularFile(
  signatureInput,
  64,
  "provider registry signature",
);
const publicKeyBytes = readBoundedRegularFile(
  publicKeyInput,
  16 * 1024,
  "provider registry public key",
);
verifySecurityReviewSignature(registryBytes, signatureBytes, publicKeyBytes);

process.stdout.write("provider registry signature verified\n");
