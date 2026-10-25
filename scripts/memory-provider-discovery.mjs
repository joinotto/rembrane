const operationBindings = Object.freeze({
  resolve_context: ["memory:context:read", "POST", "/v1/context/resolve"],
  resolve_question: ["memory:question:read", "POST", "/v1/questions/resolve"],
  record_event: ["memory:event:write", "POST", "/v1/events"],
  propose_memory: ["memory:proposal:write", "POST", "/v1/memory/proposals"],
  checkpoint_activity: [
    "memory:checkpoint:write",
    "POST",
    "/v1/activities/{activity_id}/checkpoint",
  ],
  record_disclosure: [
    "memory:disclosure:write",
    "POST",
    "/v1/disclosures/receipt",
  ],
  delete_memory: [
    "memory:memory:delete",
    "DELETE",
    "/v1/memories/{memory_id}",
  ],
  explain_memory: [
    "memory:memory:explain",
    "GET",
    "/v1/memories/{memory_id}/explain",
  ],
  sync_pull: ["memory:sync:read", "GET", "/v1/sync/pull"],
  sync_push: ["memory:sync:write", "POST", "/v1/sync/push"],
});

const manifestKeys = [
  "providerId",
  "providerVersion",
  "protocolVersion",
  "transports",
  "capabilities",
  "privacyMode",
  "supportedDomains",
  "limits",
  "operations",
];
const limitKeys = [
  "maximumContextItems",
  "maximumContextBytes",
  "maximumEventBatchItems",
  "maximumSyncBatchItems",
];
const operationKeys = [
  "operation",
  "capability",
  "oauthScope",
  "httpMethod",
  "pathTemplate",
];

export function validateMemoryProviderDiscovery(value) {
  if (
    !isExactObject(value, manifestKeys) ||
    !isPortableId(value.providerId) ||
    !isPrintableAscii(value.providerVersion, 100) ||
    value.protocolVersion !== "0.1" ||
    !isUniqueEnumList(value.transports, new Set(["https", "mcp"]), true) ||
    !isUniqueEnumList(
      value.capabilities,
      new Set(Object.keys(operationBindings)),
      true,
    ) ||
    !new Set([
      "end_to_end_encrypted",
      "trusted_boundary",
      "provider_plaintext",
    ]).has(value.privacyMode) ||
    !isUniquePortableIdList(value.supportedDomains) ||
    !isExactObject(value.limits, limitKeys) ||
    !limitKeys.every(
      (key) => Number.isSafeInteger(value.limits[key]) && value.limits[key] > 0,
    ) ||
    !Array.isArray(value.operations) ||
    value.operations.length === 0 ||
    !value.operations.every(validOperationBinding)
  ) {
    throw new Error("provider discovery is not conformance-compatible");
  }

  const advertised = new Set(value.capabilities);
  const bound = new Set(value.operations.map((operation) => operation.operation));
  if (
    value.operations.length !== bound.size ||
    advertised.size !== bound.size ||
    ![...advertised].every((capability) => bound.has(capability))
  ) {
    throw new Error("provider discovery is not conformance-compatible");
  }
  return value;
}

function validOperationBinding(value) {
  if (!isExactObject(value, operationKeys)) return false;
  const expected = operationBindings[value.operation];
  return (
    expected !== undefined &&
    value.capability === value.operation &&
    value.oauthScope === expected[0] &&
    value.httpMethod === expected[1] &&
    value.pathTemplate === expected[2]
  );
}

function isExactObject(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
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

function isPrintableAscii(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum &&
    /^[\x20-\x7e]+$/u.test(value)
  );
}

function isUniqueEnumList(value, allowed, requireItem) {
  return (
    Array.isArray(value) &&
    (!requireItem || value.length > 0) &&
    new Set(value).size === value.length &&
    value.every((item) => allowed.has(item))
  );
}

function isUniquePortableIdList(value) {
  return (
    Array.isArray(value) &&
    new Set(value).size === value.length &&
    value.every(isPortableId)
  );
}
