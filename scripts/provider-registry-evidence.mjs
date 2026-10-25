import { createHash } from "node:crypto";

const caseIds = [
  "manifest.compatible",
  "index.visible",
  "workspace.isolated",
  "replacement.exact",
  "stale-delete.preserves-current",
  "exact-delete.propagates",
];

export function parseProviderRegistry(
  registryBytes,
  profileBytes,
  now = Date.now(),
) {
  let registry;
  try {
    registry = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(registryBytes),
    );
  } catch {
    throw new Error("provider registry must be valid UTF-8 JSON");
  }
  requireExactKeys(registry, ["generatedAt", "providers", "schemaVersion"]);
  const generatedAt = canonicalTimestamp(registry.generatedAt);
  if (
    registry.schemaVersion !== 1 ||
    generatedAt === undefined ||
    generatedAt > now ||
    !Array.isArray(registry.providers)
  ) {
    throw new Error("provider registry header is invalid");
  }

  const profileSha256 = sha256(profileBytes);
  const providerIds = new Set();
  for (const provider of registry.providers) {
    const providerKeys = [
      "adapterVersion",
      "conformance",
      "deploymentModes",
      "id",
      "plaintextProcessing",
      "protocolVersions",
      "source",
      "status",
    ];
    if (provider?.revocation !== undefined) providerKeys.push("revocation");
    requireExactKeys(provider, providerKeys);
    if (
      !/^[a-z0-9][a-z0-9._-]+$/.test(provider.id) ||
      provider.id.length > 255 ||
      providerIds.has(provider.id) ||
      !safeText(provider.adapterVersion, 100) ||
      typeof provider.plaintextProcessing !== "boolean" ||
      !["experimental", "compatible", "deprecated", "revoked"].includes(
        provider.status,
      )
    ) {
      throw new Error("provider registry entry identity is invalid");
    }
    providerIds.add(provider.id);
    verifySource(provider.source);
    verifyStringSet(provider.protocolVersions, /^[0-9]+\.[0-9]+$/, 100);
    verifyStringSet(
      provider.deploymentModes,
      /^(embedded|local-service|self-hosted|managed)$/,
      4,
    );

    const conformance = provider.conformance;
    const conformanceKeys = [
      "cases",
      "namespace",
      "profileSha256",
      "protocolVersion",
      "providerVersion",
      "result",
      "suiteId",
      "suiteVersion",
      "testedAt",
    ];
    if (conformance?.notes !== undefined) conformanceKeys.push("notes");
    requireExactKeys(conformance, conformanceKeys);
    const testedAt = canonicalTimestamp(conformance.testedAt);
    if (
      !["pass", "fail"].includes(conformance.result) ||
      testedAt === undefined ||
      testedAt > now ||
      testedAt > generatedAt ||
      conformance.suiteId !== "rembrane.semantic-provider.core" ||
      conformance.suiteVersion !== "0.1" ||
      conformance.profileSha256 !== profileSha256 ||
      conformance.providerVersion !== provider.adapterVersion ||
      conformance.protocolVersion !== "0.1" ||
      !provider.protocolVersions.includes(conformance.protocolVersion) ||
      !/^[A-Za-z0-9._-]{1,100}$/.test(conformance.namespace) ||
      !optionalText(conformance.notes, 1_000) ||
      !Array.isArray(conformance.cases) ||
      conformance.cases.length !== caseIds.length
    ) {
      throw new Error("provider registry conformance identity is invalid");
    }
    for (const [index, result] of conformance.cases.entries()) {
      requireExactKeys(result, ["id", "result"]);
      if (
        result.id !== caseIds[index] ||
        !["pass", "fail"].includes(result.result)
      ) {
        throw new Error("provider registry conformance cases are invalid");
      }
    }
    if (
      (conformance.result === "pass" &&
        conformance.cases.some((result) => result.result !== "pass")) ||
      (conformance.result === "fail" &&
        conformance.cases.every((result) => result.result !== "fail")) ||
      (provider.status === "compatible" && conformance.result !== "pass")
    ) {
      throw new Error("provider registry conformance result is inconsistent");
    }
    verifyRevocation(provider, testedAt, generatedAt);
  }
  return registry;
}

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function verifySource(source) {
  requireExactKeys(source, ["repository", "revision"]);
  let repository;
  try {
    repository = new URL(source.repository);
  } catch {
    throw new Error("provider registry source is invalid");
  }
  if (
    repository.protocol !== "https:" ||
    repository.username !== "" ||
    repository.password !== "" ||
    repository.hash !== "" ||
    !/^[0-9a-f]{7,64}$/.test(source.revision)
  ) {
    throw new Error("provider registry source is invalid");
  }
}

function verifyStringSet(value, pattern, maximum) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > maximum ||
    new Set(value).size !== value.length ||
    value.some((item) => typeof item !== "string" || !pattern.test(item))
  ) {
    throw new Error("provider registry capability set is invalid");
  }
}

function verifyRevocation(provider, testedAt, generatedAt) {
  if (provider.status !== "revoked") {
    if (provider.revocation !== undefined) {
      throw new Error("active provider contains revocation metadata");
    }
    return;
  }
  const keys = ["reason", "revokedAt"];
  if (provider.revocation?.details !== undefined) keys.push("details");
  requireExactKeys(provider.revocation, keys);
  const revokedAt = canonicalTimestamp(provider.revocation.revokedAt);
  if (
    revokedAt === undefined ||
    revokedAt < testedAt ||
    revokedAt > generatedAt ||
    ![
      "compromised",
      "incompatible",
      "policy-violation",
      "superseded",
      "unmaintained",
    ].includes(provider.revocation.reason) ||
    !optionalText(provider.revocation.details, 1_000)
  ) {
    throw new Error("provider registry revocation is invalid");
  }
}

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("provider registry contains unexpected fields");
  }
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

function optionalText(value, maximum) {
  return value === undefined || safeText(value, maximum);
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
