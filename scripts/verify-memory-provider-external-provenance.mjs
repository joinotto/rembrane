import { verifyExternalProviderProvenance } from "./memory-provider-external-provenance.mjs";
import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const [provenanceInput, resultInput, signatureInput, publicKeyInput] =
  process.argv.slice(2);
if (!provenanceInput || !resultInput || !signatureInput || !publicKeyInput) {
  throw new Error(
    "usage: verify-memory-provider-external-provenance.mjs PROVENANCE RESULT SIGNATURE PUBLIC_KEY",
  );
}

const provenanceBytes = readBoundedRegularFile(
  provenanceInput,
  16 * 1024,
  "external provider provenance",
);
const resultBytes = readBoundedRegularFile(
  resultInput,
  128 * 1024,
  "external provider result",
);
const signatureBytes = readBoundedRegularFile(
  signatureInput,
  64,
  "external provider signature",
);
const publicKeyBytes = readBoundedRegularFile(
  publicKeyInput,
  16 * 1024,
  "external provider public key",
);
verifyExternalProviderProvenance({
  provenanceBytes,
  resultBytes,
  signatureBytes,
  publicKeyBytes,
});

process.stdout.write("external memory-provider provenance verified\n");
