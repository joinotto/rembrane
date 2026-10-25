import { writeEd25519PublicKey } from "./ed25519-signing.mjs";

const [privateKeyInput, output] = process.argv.slice(2);
if (!privateKeyInput || !output || process.argv.length !== 4) {
  throw new Error(
    "usage: derive-ed25519-public-key.mjs PRIVATE_KEY OUTPUT",
  );
}
writeEd25519PublicKey(privateKeyInput, output);
