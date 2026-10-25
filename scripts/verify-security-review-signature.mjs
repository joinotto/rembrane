import { createPublicKey, verify } from "node:crypto";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

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

let valid = false;
try {
  const publicKey = createPublicKey(publicKeyBytes);
  valid =
    publicKey.asymmetricKeyType === "ed25519" &&
    signatureBytes.length === 64 &&
    verify(null, documentBytes, publicKey, signatureBytes);
} catch {
  valid = false;
}
if (!valid) throw new Error("security review signature is invalid");

process.stdout.write("security review signature verified\n");
