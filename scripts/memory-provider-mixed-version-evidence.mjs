import { createHash } from "node:crypto";

export function verifyMemoryProviderMixedVersionEvidence({
  evidenceBytes,
  profileBytes,
  fixtureBytes,
  now = Date.now(),
}) {
  let evidence;
  try {
    evidence = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes),
    );
  } catch {
    throw new Error("memory-provider mixed-version evidence is invalid");
  }
  requireExactKeys(evidence, [
    "fixtureSha256",
    "generatedAt",
    "harnessSourceRevision",
    "newestSupportedMinor",
    "oldestSupportedMinor",
    "profileSha256",
    "runs",
    "schemaVersion",
  ]);

  const generatedAt = canonicalTimestamp(evidence.generatedAt);
  const oldest = parseProtocolVersion(evidence.oldestSupportedMinor);
  const newest = parseProtocolVersion(evidence.newestSupportedMinor);
  if (
    evidence.schemaVersion !== 1 ||
    generatedAt === undefined ||
    generatedAt > now + 5 * 60 * 1000 ||
    !/^[0-9a-f]{40}$/.test(evidence.harnessSourceRevision) ||
    evidence.profileSha256 !== sha256(profileBytes) ||
    evidence.fixtureSha256 !== sha256(fixtureBytes) ||
    oldest === undefined ||
    newest === undefined ||
    oldest.major !== newest.major ||
    oldest.minor >= newest.minor ||
    !Array.isArray(evidence.runs) ||
    evidence.runs.length !== 3
  ) {
    throw new Error("memory-provider mixed-version evidence header is invalid");
  }

  const expectedScenarios = [
    "oldest-client-newest-provider",
    "newest-client-oldest-provider",
    "unsupported-major",
  ];
  const namespaces = new Set();
  for (const [index, run] of evidence.runs.entries()) {
    requireExactKeys(run, [
      "client",
      "namespace",
      "provider",
      "result",
      "scenario",
    ]);
    requireImplementation(run.client);
    requireImplementation(run.provider);
    if (
      run.scenario !== expectedScenarios[index] ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(run.namespace) ||
      namespaces.has(run.namespace)
    ) {
      throw new Error("memory-provider compatibility run identity is invalid");
    }
    namespaces.add(run.namespace);
  }

  const [oldClient, newClient, majorMismatch] = evidence.runs;
  if (
    oldClient.client.protocolVersion !== evidence.oldestSupportedMinor ||
    oldClient.provider.protocolVersion !== evidence.newestSupportedMinor ||
    oldClient.result !== "pass" ||
    newClient.client.protocolVersion !== evidence.newestSupportedMinor ||
    newClient.provider.protocolVersion !== evidence.oldestSupportedMinor ||
    newClient.result !== "pass"
  ) {
    throw new Error("memory-provider supported-minor evidence is invalid");
  }

  const mismatchClient = parseProtocolVersion(
    majorMismatch.client.protocolVersion,
  );
  const mismatchProvider = parseProtocolVersion(
    majorMismatch.provider.protocolVersion,
  );
  if (
    mismatchClient === undefined ||
    mismatchProvider === undefined ||
    mismatchClient.major === mismatchProvider.major ||
    majorMismatch.result !== "rejected"
  ) {
    throw new Error("memory-provider major-version rejection evidence is invalid");
  }
  return evidence;
}

function requireExactKeys(value, expected) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== expected.sort().join(",")
  ) {
    throw new Error("memory-provider evidence contains unexpected fields");
  }
}

function requireImplementation(value) {
  requireExactKeys(value, [
    "buildVersion",
    "id",
    "protocolVersion",
    "sourceRevision",
  ]);
  if (
    !/^[a-z0-9][a-z0-9._-]+$/.test(value.id) ||
    value.id.length > 255 ||
    !safeText(value.buildVersion, 100) ||
    !/^[0-9a-f]{40}$/.test(value.sourceRevision) ||
    parseProtocolVersion(value.protocolVersion) === undefined
  ) {
    throw new Error(
      "memory-provider compatibility implementation is invalid",
    );
  }
}

function parseProtocolVersion(value) {
  const match =
    typeof value === "string" && /^([0-9]+)\.([0-9]+)$/.exec(value);
  if (!match || value.length > 21) return undefined;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (
    !Number.isSafeInteger(major) ||
    !Number.isSafeInteger(minor) ||
    String(major) !== match[1] ||
    String(minor) !== match[2]
  ) {
    return undefined;
  }
  return { major, minor };
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
