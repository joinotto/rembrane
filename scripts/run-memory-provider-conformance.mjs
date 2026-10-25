import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveConformanceToken } from "./memory-provider-conformance-secrets.mjs";
import {
  isSafeMemoryProviderBase,
  validateMemoryProviderDiscovery,
} from "./memory-provider-discovery.mjs";

const namespace = process.argv[2];
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const base = new URL(required("REMBRANE_MEMORY_PROVIDER_BASE_URL"));
let tokens;
const profilePath =
  process.env.REMBRANE_MEMORY_PROVIDER_PROFILE_FILE ??
  resolve(root, "spec/conformance/memory-provider-core.json");
const fixturePath =
  process.env.REMBRANE_MEMORY_PROVIDER_FIXTURE_FILE ??
  resolve(root, "spec/conformance/memory-provider-core-fixtures.json");

if (
  !/^[A-Za-z0-9._-]{1,64}$/.test(namespace ?? "") ||
  !isSafeMemoryProviderBase(base)
) {
  throw new Error("memory-provider conformance configuration is invalid");
}

const profileBytes = await readFile(profilePath);
const fixtureBytes = await readFile(fixturePath);
const canonicalProfileBytes = await readFile(
  resolve(root, "spec/conformance/memory-provider-core.json"),
);
const canonicalFixtureBytes = await readFile(
  resolve(root, "spec/conformance/memory-provider-core-fixtures.json"),
);
if (profileBytes.length > 128 * 1024 || fixtureBytes.length > 256 * 1024) {
  throw new Error("memory-provider conformance artifacts exceed limits");
}
if (
  sha256(profileBytes) !== sha256(canonicalProfileBytes) ||
  sha256(fixtureBytes) !== sha256(canonicalFixtureBytes)
) {
  throw new Error(
    "memory-provider conformance inputs must match the reviewed profile and fixture",
  );
}
const profile = JSON.parse(profileBytes);
const fixtures = JSON.parse(fixtureBytes);
if (
  profile.profileId !== "rembrane.memory-provider.core" ||
  profile.protocolVersion !== "0.1" ||
  fixtures.profileId !== profile.profileId ||
  fixtures.fixtureId !== "rembrane.memory-provider.core.lifecycle" ||
  fixtures.protocolVersion !== profile.protocolVersion ||
  !Array.isArray(profile.cases) ||
  profile.cases.length === 0
) {
  throw new Error("memory-provider conformance artifacts are incompatible");
}

const scenario = fixtures.scenario;
const created = [];
let provider;
try {
  const discovery = await call("discovery", undefined, "GET", "/.well-known/ai-memory");
  expectStatus(discovery, 200, "discovery.public");
  provider = validateMemoryProviderDiscovery(discovery.value);
  const requiredCapabilities = [
    "resolve_context",
    "propose_memory",
    "delete_memory",
    "sync_pull",
  ];
  if (
    !requiredCapabilities.every((value) => provider.capabilities?.includes(value))
  ) {
    throw new Error("provider discovery is not conformance-compatible");
  }
  tokens = {
    primary: await resolveConformanceToken("PRIMARY"),
    other: await resolveConformanceToken("OTHER"),
    readonly: await resolveConformanceToken("READONLY"),
  };
  if (
    Object.values(tokens).some(
      (token) => !/^[A-Za-z0-9._~+/=-]+$/.test(token) || token.length > 8192,
    ) ||
    new Set(Object.values(tokens)).size !== 3
  ) {
    throw new Error("memory-provider conformance configuration is invalid");
  }
  const maximumItems = Math.min(
    positive(provider.limits?.maximumContextItems),
    positive(scenario.maximumContextItems),
  );
  const maximumBytes = Math.min(
    positive(provider.limits?.maximumContextBytes),
    positive(scenario.maximumContextBytes),
  );
  const maximumSyncItems = Math.min(
    positive(provider.limits?.maximumSyncBatchItems),
    positive(scenario.maximumSyncItems),
  );
  const query = `${scenario.contentPrefix}-${namespace}`;
  const context = (value) => ({
    purpose: scenario.contextPurpose,
    query: value,
    selector: { scope: "global" },
    maximumItems,
    maximumBytes,
  });

  const missingToken = await call(
    "missing_token",
    undefined,
    "POST",
    "/v1/context/resolve",
    context(query),
  );
  expectStatus(missingToken, 401, "protected.missing-token");
  requireProtocolError(missingToken.value, "access_denied");

  const primaryProposal = proposal("primary");
  const insufficientScope = await call(
    "insufficient_scope",
    tokens.readonly,
    "POST",
    "/v1/memory/proposals",
    primaryProposal,
  );
  expectStatus(insufficientScope, 403, "scope.insufficient");
  requireProtocolError(insufficientScope.value, "access_denied");
  const first = await call(
    "propose_primary",
    tokens.primary,
    "POST",
    "/v1/memory/proposals",
    primaryProposal,
  );
  expectStatus(first, 200, "proposal.accepted");
  requireMemoryResult(first.value);
  created.push({ token: tokens.primary, ...first.value, label: "primary" });

  const replay = await call(
    "propose_repeat",
    tokens.primary,
    "POST",
    "/v1/memory/proposals",
    primaryProposal,
  );
  expectStatus(replay, 200, "proposal.idempotent");
  requireMemoryResult(replay.value);
  if (
    replay.value.memoryId !== first.value.memoryId ||
    replay.value.version !== first.value.version
  ) {
    throw new Error("proposal replay created a different memory");
  }

  const otherProposal = proposal("other");
  const other = await call(
    "propose_other",
    tokens.other,
    "POST",
    "/v1/memory/proposals",
    otherProposal,
  );
  expectStatus(other, 200, "context.cross-workspace");
  requireMemoryResult(other.value);
  created.push({ token: tokens.other, ...other.value, label: "other" });

  const primaryContext = await call(
    "context_primary",
    tokens.primary,
    "POST",
    "/v1/context/resolve",
    context(primaryProposal.content),
  );
  expectStatus(primaryContext, 200, "context.exact-workspace");
  requireContextResult(primaryContext.value);
  if (
    !primaryContext.value.items?.some(
      (item) =>
        item.memoryId === first.value.memoryId &&
        item.content === primaryProposal.content,
    )
  ) {
    throw new Error("primary workspace did not return its conformance memory");
  }
  const otherContext = await call(
    "context_other",
    tokens.other,
    "POST",
    "/v1/context/resolve",
    context(primaryProposal.content),
  );
  expectStatus(otherContext, 200, "context.cross-workspace");
  requireContextResult(otherContext.value);
  if (
    otherContext.value.items?.some(
      (item) =>
        item.memoryId === first.value.memoryId ||
        item.content === primaryProposal.content,
    )
  ) {
    throw new Error("conformance memory crossed a workspace boundary");
  }

  const stale = deletion(first.value, "stale", first.value.version + 1);
  const staleDeletion = await call(
    "delete_stale",
    tokens.primary,
    "DELETE",
    `/v1/memories/${encodeURIComponent(first.value.memoryId)}`,
    stale,
  );
  expectStatus(staleDeletion, 409, "delete.stale-version");
  requireProtocolError(staleDeletion.value, "conflict");
  const preserved = await call(
    "context_after_conflict",
    tokens.primary,
    "POST",
    "/v1/context/resolve",
    context(primaryProposal.content),
  );
  requireContextResult(preserved.value);
  if (!preserved.value.items?.some((item) => item.memoryId === first.value.memoryId)) {
    throw new Error("stale deletion changed the current memory");
  }

  const sync = await call(
    "sync_primary",
    tokens.primary,
    "GET",
    `/v1/sync/pull?maximumItems=${maximumSyncItems}`,
  );
  expectStatus(sync, 200, "sync.workspace-isolation");
  const changes = sync.value.changes;
  if (
    !Array.isArray(changes) ||
    changes.some((change) => change.resourceId === other.value.memoryId) ||
    new Set(changes.map((change) => change.changeId)).size !== changes.length ||
    changes.some(
      (change, index) =>
        !Number.isSafeInteger(change.sequence) ||
        change.sequence < 1 ||
        (index > 0 && changes[index - 1].sequence >= change.sequence),
    )
  ) {
    throw new Error("sync results are not isolated and strictly ordered");
  }

  const exact = await call(
    "delete_exact",
    tokens.primary,
    "DELETE",
    `/v1/memories/${encodeURIComponent(first.value.memoryId)}`,
    deletion(first.value, "exact", first.value.version),
  );
  expectStatus(exact, 200, "delete.exact-version");
  requireDeleteResult(exact.value);
  if (
    exact.value.memoryId !== first.value.memoryId ||
    exact.value.deletedVersion !== first.value.version ||
    exact.value.tombstoneVersion !== first.value.version + 1
  ) {
    throw new Error("exact deletion returned an invalid tombstone");
  }
  created.shift();
  const afterDelete = await call(
    "context_after_delete",
    tokens.primary,
    "POST",
    "/v1/context/resolve",
    context(primaryProposal.content),
  );
  requireContextResult(afterDelete.value);
  if (afterDelete.value.items?.some((item) => item.content === primaryProposal.content)) {
    throw new Error("deleted conformance memory remained visible");
  }

  process.stdout.write(
    `${JSON.stringify({
      profileId: profile.profileId,
      profileSha256: sha256(profileBytes),
      fixtureId: fixtures.fixtureId,
      fixtureSha256: sha256(fixtureBytes),
      protocolVersion: profile.protocolVersion,
      provider: { id: provider.providerId, version: provider.providerVersion },
      result: "pass",
      namespace,
      cases: profile.cases.map(({ id }) => ({ id, result: "pass" })),
    })}\n`,
  );
} finally {
  for (const memory of created) {
    await call(
      `cleanup_${memory.label}`,
      memory.token,
      "DELETE",
      `/v1/memories/${encodeURIComponent(memory.memoryId)}`,
      deletion(memory, "cleanup", memory.version),
    ).catch(() => undefined);
  }
}

function proposal(label) {
  return {
    idempotencyKey: `proposal_${namespace}_${label}`,
    selector: { scope: "global" },
    kind: "semantic",
    content: `${scenario.contentPrefix}-${namespace}-${label}`,
    evidenceSource: scenario.evidenceSource,
    sourceReference: scenario.sourceReference,
    observedAtEpochSeconds: positive(scenario.observedAtEpochSeconds),
  };
}

function deletion(memory, label, expectedVersion) {
  return {
    idempotencyKey: `delete_${namespace}_${label}`,
    memoryId: memory.memoryId,
    expectedVersion,
    reason:
      label === "stale"
        ? scenario.staleDeleteReason
        : label === "exact"
          ? scenario.exactDeleteReason
          : scenario.cleanupDeleteReason,
  };
}

async function call(label, token, method, path, body) {
  const requestId = `conformance_${namespace}_${label}`.slice(0, 128);
  const headers = {
    accept: "application/json",
    "x-rembrane-request-id": requestId,
    "x-rembrane-protocol-version": "0.1",
  };
  if (token !== undefined) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(new URL(path, base), {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  const value = await boundedJson(response, 1_500_000);
  if (
    response.headers.get("x-rembrane-request-id") !== requestId ||
    response.headers.get("x-rembrane-protocol-version") !== "0.1"
  ) {
    throw new Error("memory-provider response correlation mismatch");
  }
  return { status: response.status, value };
}

async function boundedJson(response, maximum) {
  const contentType = response.headers.get("content-type");
  if (
    contentType === null ||
    contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json"
  ) {
    throw new Error("memory-provider response is not JSON");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("memory-provider response body is missing");
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > maximum) {
      await reader.cancel();
      throw new Error("memory-provider response exceeds the transport limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function expectStatus(response, expected, name) {
  if (response.status !== expected) {
    throw new Error(`${name} returned HTTP ${response.status}`);
  }
}

function requireMemoryResult(value) {
  if (
    !hasExactKeys(value, ["memoryId", "version"]) ||
    !isSafeOpaqueId(value.memoryId) ||
    !Number.isSafeInteger(value.version) ||
    value.version < 1
  ) {
    throw new Error("proposal returned an invalid memory identity");
  }
}

function requireDeleteResult(value) {
  if (
    !hasExactKeys(value, ["memoryId", "deletedVersion", "tombstoneVersion"]) ||
    !isSafeOpaqueId(value.memoryId) ||
    !Number.isSafeInteger(value.deletedVersion) ||
    value.deletedVersion < 1 ||
    !Number.isSafeInteger(value.tombstoneVersion) ||
    value.tombstoneVersion < 1
  ) {
    throw new Error("deletion returned an invalid closed result");
  }
}

function requireContextResult(value) {
  if (
    !hasExactKeys(value, ["contextPackId", "disclosureId", "items"]) ||
    !isSafeOpaqueId(value.contextPackId) ||
    !isSafeOpaqueId(value.disclosureId) ||
    !Array.isArray(value.items) ||
    !value.items.every(validContextItem)
  ) {
    throw new Error("memory-provider returned an invalid closed context result");
  }
}

function validContextItem(value) {
  const required = [
    "memoryId",
    "version",
    "scope",
    "kind",
    "content",
    "evidence",
    "confidenceMillionths",
    "sensitivity",
    "disclosureConstraints",
  ];
  const allowed = [...required, "validFromEpochSeconds", "validUntilEpochSeconds"];
  return (
    hasRequiredOnlyKeys(value, required, allowed) &&
    isSafeOpaqueId(value.memoryId) &&
    Number.isSafeInteger(value.version) &&
    value.version > 0 &&
    validSelector(value.scope) &&
    new Set([
      "preference",
      "semantic",
      "episodic",
      "procedural",
      "observation",
      "working",
    ]).has(value.kind) &&
    typeof value.content === "string" &&
    value.content.length > 0 &&
    new TextEncoder().encode(value.content).length <= 262_144 &&
    !value.content.includes("\0") &&
    Array.isArray(value.evidence) &&
    value.evidence.length > 0 &&
    uniqueObjects(value.evidence) &&
    value.evidence.every(
      (evidence) =>
        hasExactKeys(evidence, ["evidenceId", "source"]) &&
        isSafeOpaqueId(evidence.evidenceId) &&
        new Set([
          "user_statement",
          "agent_observation",
          "tool_result",
          "imported_record",
          "workspace_decision",
        ]).has(evidence.source),
    ) &&
    Number.isSafeInteger(value.confidenceMillionths) &&
    value.confidenceMillionths >= 0 &&
    value.confidenceMillionths <= 1_000_000 &&
    validOptionalEpoch(value.validFromEpochSeconds) &&
    validOptionalEpoch(value.validUntilEpochSeconds) &&
    new Set(["personal", "sensitive", "restricted"]).has(value.sensitivity) &&
    Array.isArray(value.disclosureConstraints) &&
    uniqueObjects(value.disclosureConstraints) &&
    value.disclosureConstraints.every(validDisclosureConstraint)
  );
}

function validSelector(value) {
  return (
    (hasExactKeys(value, ["scope"]) && value.scope === "global") ||
    (hasExactKeys(value, ["scope", "domain"]) &&
      value.scope === "domain" &&
      isPortableId(value.domain)) ||
    (hasExactKeys(value, ["scope", "entityId"]) &&
      value.scope === "entity" &&
      isSafeOpaqueId(value.entityId)) ||
    (hasExactKeys(value, ["scope", "activityId"]) &&
      value.scope === "activity" &&
      isSafeOpaqueId(value.activityId))
  );
}

function validDisclosureConstraint(value) {
  return (
    (hasExactKeys(value, ["type"]) &&
      new Set(["purpose_bound", "no_training", "no_retention"]).has(value.type)) ||
    (hasExactKeys(value, ["type", "expiresAtEpochSeconds"]) &&
      value.type === "expires_at" &&
      Number.isSafeInteger(value.expiresAtEpochSeconds) &&
      value.expiresAtEpochSeconds > 0)
  );
}

function validOptionalEpoch(value) {
  return value === undefined || value === null || (Number.isSafeInteger(value) && value > 0);
}

function uniqueObjects(value) {
  return new Set(value.map((item) => JSON.stringify(item))).size === value.length;
}

function requireProtocolError(value, expectedCode) {
  if (
    !hasExactKeys(value, ["code"]) ||
    value.code !== expectedCode
  ) {
    throw new Error("memory-provider returned an invalid closed error response");
  }
}

function hasRequiredOnlyKeys(value, required, allowed) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  const allowedKeys = new Set(allowed);
  return required.every((key) => keys.includes(key)) &&
    keys.every((key) => allowedKeys.has(key));
}

function hasExactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function isSafeOpaqueId(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 255 &&
    /^[\x21-\x7e]+$/u.test(value)
  );
}

function isPortableId(value) {
  return (
    typeof value === "string" &&
    value.length >= 2 &&
    value.length <= 255 &&
    /^[a-z0-9][a-z0-9._-]+$/u.test(value)
  );
}

function positive(value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("memory-provider conformance limit is invalid");
  }
  return value;
}

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
