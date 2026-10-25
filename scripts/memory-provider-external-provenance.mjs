import { createHash } from "node:crypto";

import { verifyEd25519Signature } from "./ed25519-verification.mjs";

export function verifyExternalProviderProvenance({
  provenanceBytes,
  resultBytes,
  signatureBytes,
  publicKeyBytes,
  now = Date.now(),
}) {
  let provenance;
  try {
    provenance = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(provenanceBytes),
    );
  } catch {
    throw new Error("external provider provenance is invalid");
  }
  if (
    provenance === null ||
    typeof provenance !== "object" ||
    Array.isArray(provenance) ||
    Object.keys(provenance).sort().join(",") !==
      [
        "maintainerId",
        "resultSha256",
        "schemaVersion",
        "signedAt",
        "sourceRevision",
      ]
        .sort()
        .join(",") ||
    provenance.schemaVersion !== 1 ||
    !safeText(provenance.maintainerId, 200) ||
    !/^[0-9a-f]{40}$/.test(provenance.sourceRevision) ||
    provenance.resultSha256 !== sha256(resultBytes) ||
    canonicalTimestamp(provenance.signedAt) === undefined ||
    canonicalTimestamp(provenance.signedAt) > now + 5 * 60 * 1000
  ) {
    throw new Error("external provider provenance is invalid");
  }

  try {
    verifyEd25519Signature(
      provenanceBytes,
      signatureBytes,
      publicKeyBytes,
    );
  } catch {
    throw new Error("external provider provenance signature is invalid");
  }
  return provenance;
}

function safeText(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    /^[ -~]+$/.test(value) &&
    value.trim() === value
  );
}

function canonicalTimestamp(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
  ) {
    return undefined;
  }
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) &&
    new Date(epoch).toISOString().replace(".000Z", "Z") === value
    ? epoch
    : undefined;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
