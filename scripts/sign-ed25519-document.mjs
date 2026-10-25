import { signEd25519Document } from "./ed25519-signing.mjs";

const [documentInput, privateKeyInput, output] = process.argv.slice(2);
if (!documentInput || !privateKeyInput || !output || process.argv.length !== 5) {
  throw new Error(
    "usage: sign-ed25519-document.mjs DOCUMENT PRIVATE_KEY OUTPUT",
  );
}
signEd25519Document(documentInput, privateKeyInput, output);
