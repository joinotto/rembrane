import { createPublicKey, verify } from "node:crypto";

export function verifyEd25519Signature(
  documentBytes,
  signatureBytes,
  publicKeyBytes,
) {
  let valid = false;
  try {
    const pem = new TextDecoder("utf-8", { fatal: true }).decode(publicKeyBytes);
    if (
      !pem.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
      !pem.endsWith("-----END PUBLIC KEY-----\n") ||
      pem.includes("PRIVATE KEY")
    ) {
      throw new Error();
    }
    const publicKey = createPublicKey(publicKeyBytes);
    valid =
      publicKey.type === "public" &&
      publicKey.asymmetricKeyType === "ed25519" &&
      signatureBytes.length === 64 &&
      verify(null, documentBytes, publicKey, signatureBytes);
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("Ed25519 signature is invalid");
}
