import {
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import { writeFileSync } from "node:fs";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

export function signEd25519Document(documentInput, privateKeyInput, output) {
  const documentBytes = readBoundedRegularFile(
    documentInput,
    16 * 1024 * 1024,
    "signing document",
  );
  const privateKey = loadPrivateKey(privateKeyInput);
  const signature = sign(null, documentBytes, privateKey);
  if (signature.length !== 64) throw new Error("Ed25519 signing failed");
  writeFileSync(output, signature, { flag: "wx", mode: 0o600 });
}

export function writeEd25519PublicKey(privateKeyInput, output) {
  const privateKey = loadPrivateKey(privateKeyInput);
  const publicKey = createPublicKey(privateKey).export({
    type: "spki",
    format: "pem",
  });
  writeFileSync(output, publicKey, { flag: "wx", mode: 0o600 });
}

function loadPrivateKey(input) {
  const bytes = readBoundedRegularFile(
    input,
    16 * 1024,
    "Ed25519 private key",
    { allowedModes: [0o400, 0o600] },
  );
  try {
    const key = createPrivateKey(bytes);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error("signing key is not Ed25519");
    }
    return key;
  } finally {
    bytes.fill(0);
  }
}
