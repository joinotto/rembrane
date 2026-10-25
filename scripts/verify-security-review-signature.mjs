import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";
import { verifySecurityReviewSignature } from "./security-review-evidence.mjs";

const [documentInput, signatureInput, publicKeyInput] = process.argv.slice(2);
if (!documentInput || !signatureInput || !publicKeyInput) {
  throw new Error(
    "usage: verify-security-review-signature.mjs DOCUMENT SIGNATURE PUBLIC_KEY",
  );
}

const documentBytes = readBoundedRegularFile(
  documentInput,
  16 * 1024 * 1024,
  "security review document",
);
const signatureBytes = readBoundedRegularFile(
  signatureInput,
  64,
  "security review signature",
);
const publicKeyBytes = readBoundedRegularFile(
  publicKeyInput,
  16 * 1024,
  "security review public key",
);

verifySecurityReviewSignature(documentBytes, signatureBytes, publicKeyBytes);

process.stdout.write("security review signature verified\n");
