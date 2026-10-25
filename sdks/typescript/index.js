const DEFAULT_MAXIMUM_RESPONSE_BYTES = 1024 * 1024;
const CHANNEL_PROCESSOR_PROTOCOL_VERSION = "0.1";
const CHANNEL_PROCESSOR_CHANNELS = new Set([
  "whatsapp-business",
  "imessage-extension",
  "mobile-share",
]);
const CHANNEL_PROCESSOR_STATUSES = new Set(["processed", "duplicate"]);
const DISCOVERY_PROCESSING_MODES = new Set([
  "hosted",
  "customer-gateway",
  "local-only",
]);
const DISCOVERY_PLAINTEXT_LOCATIONS = new Set([
  "provider",
  "customer-gateway",
  "user-device",
  "mode-dependent",
]);
const CHANNEL_MESSAGE_KEYS = [
  "channel",
  "clientId",
  "eventId",
  "principalId",
  "protocolVersion",
  "receivedAtEpochSeconds",
  "text",
  "workspaceId",
];

export class RembraneError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "RembraneError";
    this.status = status;
    this.code = code;
  }
}

export class RembraneClient {
  #baseUrl;
  #token;
  #fetch;
  #maximumResponseBytes;

  constructor(options) {
    if (!options || typeof options !== "object") {
      throw new TypeError("Rembrane client options are required");
    }
    const url = new URL(options.baseUrl);
    const loopback =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "::1";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
      throw new TypeError("Rembrane requires HTTPS or an explicit loopback URL");
    }
    if (url.username || url.password || url.search || url.hash) {
      throw new TypeError("Rembrane base URL must not contain credentials, query, or fragment");
    }
    if (typeof options.token !== "string" || options.token.length === 0) {
      throw new TypeError("Rembrane bearer token is required");
    }
    if (typeof options.fetch !== "function") {
      throw new TypeError("A Fetch API-compatible implementation is required");
    }
    const maximum = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
    if (!Number.isSafeInteger(maximum) || maximum < 1) {
      throw new TypeError("maximumResponseBytes must be a positive safe integer");
    }
    this.#baseUrl = url.toString().replace(/\/$/, "");
    this.#token = options.token;
    this.#fetch = options.fetch;
    this.#maximumResponseBytes = maximum;
  }

  resolveContext(request) {
    return this.#request("POST", "/context/resolve", request);
  }

  async discover() {
    const url = new URL("/.well-known/ai-memory", this.#baseUrl);
    const value = await this.#requestUrl("GET", url.toString(), undefined, false);
    return validateMemoryDiscovery(value, this.#baseUrl);
  }

  resolveGraphContext(request) {
    return this.#request("POST", "/graph/context/resolve", request);
  }

  rememberPreference(request) {
    return this.#request("POST", "/memories/preferences", request);
  }

  recordWorkTrace(request) {
    return this.#request("POST", "/memories/work-traces", request);
  }

  correctMemory(memoryId, request) {
    if (!isOpaqueId(memoryId)) {
      throw new TypeError("memoryId must be a bounded opaque identifier");
    }
    return this.#request(
      "POST",
      `/memories/${encodeURIComponent(memoryId)}/correction`,
      request,
    );
  }

  deleteMemory(memoryId, request) {
    if (!isOpaqueId(memoryId)) {
      throw new TypeError("memoryId must be a bounded opaque identifier");
    }
    return this.#request(
      "POST",
      `/memories/${encodeURIComponent(memoryId)}/deletion`,
      request,
    );
  }

  checkpointActivity(activityId, request) {
    if (!isOpaqueId(activityId)) {
      throw new TypeError("activityId must be a bounded opaque identifier");
    }
    return this.#request(
      "POST",
      `/activities/${encodeURIComponent(activityId)}/checkpoint`,
      request,
    );
  }

  resumeActivity(activityId, query) {
    if (!isOpaqueId(activityId)) {
      throw new TypeError("activityId must be a bounded opaque identifier");
    }
    const parameters = new URLSearchParams({
      workspaceId: query.workspaceId,
      subjectId: query.subjectId,
    });
    if (query.purpose !== undefined) {
      parameters.set("purpose", query.purpose);
    }
    if (query.stateFingerprint !== undefined) {
      parameters.set("stateFingerprint", query.stateFingerprint);
    }
    return this.#request(
      "GET",
      `/activities/${encodeURIComponent(activityId)}/resume?${parameters}`,
      undefined,
    );
  }

  createTrip(request) {
    validateTravelRequestIdentity(request, false, false);
    return this.#request("POST", "/travel/trips", request);
  }

  addTripParticipant(request) {
    validateTravelRequestIdentity(request, true, false);
    return this.#request("POST", "/travel/trip-participants", request);
  }

  addTripConstraint(request) {
    validateTravelRequestIdentity(request, true, true);
    return this.#request("POST", "/travel/trip-constraints", request);
  }

  recordTripDecision(request) {
    validateTravelRequestIdentity(request, true, false);
    return this.#request("POST", "/travel/trip-decisions", request);
  }

  captureBookingResearch(request) {
    validateTravelRequestIdentity(request, true, false);
    return this.#request("POST", "/travel/booking-research", request);
  }

  resolveTravelContext(request) {
    validateTravelRequestIdentity(request, true, false);
    return this.#request("POST", "/travel/context/resolve", request);
  }

  rotateWorkspaceKey(request) {
    return this.#request("POST", "/workspaces/key-rotation", request);
  }

  createWorkspaceInvitation(request) {
    return this.#request("POST", "/workspaces/invitations", request);
  }

  acceptWorkspaceInvitation(request) {
    return this.#request("POST", "/workspaces/invitations/accept", request);
  }

  revokeWorkspaceInvitation(request) {
    return this.#request("POST", "/workspaces/invitations/revoke", request);
  }

  listWorkspaceInvitations(query) {
    const parameters = new URLSearchParams({ workspaceId: query.workspaceId });
    if (query.status !== undefined) {
      parameters.set("status", query.status);
    }
    if (query.limit !== undefined) {
      parameters.set("limit", String(query.limit));
    }
    return this.#request("GET", `/workspaces/invitations?${parameters}`, undefined);
  }

  listAdministrativeAudit(query) {
    const parameters = new URLSearchParams({ workspaceId: query.workspaceId });
    if (query.afterEpochSeconds !== undefined) {
      parameters.set("afterEpochSeconds", String(query.afterEpochSeconds));
    }
    if (query.limit !== undefined) {
      parameters.set("limit", String(query.limit));
    }
    return this.#request("GET", `/administrative-audit?${parameters}`, undefined);
  }

  setRetentionPolicy(request) {
    return this.#request("POST", "/retention/policy", request);
  }

  placeLegalHold(request) {
    return this.#request("POST", "/retention/legal-holds", request);
  }

  releaseLegalHold(request) {
    return this.#request("POST", "/retention/legal-holds/release", request);
  }

  executeRetentionPurge(request) {
    return this.#request("POST", "/retention/purge", request);
  }

  async #request(method, path, body) {
    return this.#requestUrl(
      method,
      `${this.#baseUrl}${path}`,
      body,
      true,
    );
  }

  async #requestUrl(method, url, body, authenticated) {
    const response = await this.#fetch(url, {
      method,
      redirect: "error",
      headers: {
        Accept: "application/json",
        ...(authenticated ? { Authorization: `Bearer ${this.#token}` } : {}),
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      throw new RembraneError(response.status, "invalid_response", "Expected JSON response");
    }
    const text = await response.text();
    if (new TextEncoder().encode(text).length > this.#maximumResponseBytes) {
      throw new RembraneError(response.status, "response_too_large", "Response exceeded limit");
    }
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new RembraneError(response.status, "invalid_response", "Response was not valid JSON");
    }
    if (!response.ok) {
      throw new RembraneError(
        response.status,
        typeof value.code === "string" ? value.code : "request_failed",
        typeof value.message === "string" ? value.message : "Rembrane request failed",
      );
    }
    return value;
  }
}

export function parseChannelProcessorMessage(value) {
  if (!isExactObject(value, CHANNEL_MESSAGE_KEYS)) {
    throw new TypeError("Invalid Rembrane channel processor message");
  }
  if (
    value.protocolVersion !== CHANNEL_PROCESSOR_PROTOCOL_VERSION ||
    !CHANNEL_PROCESSOR_CHANNELS.has(value.channel) ||
    !isBoundedToken(value.eventId, 256) ||
    !isBoundedToken(value.workspaceId, 255) ||
    !isBoundedToken(value.principalId, 255) ||
    !isBoundedToken(value.clientId, 255) ||
    typeof value.text !== "string" ||
    value.text.trim().length === 0 ||
    utf8Length(value.text) > 16_384 ||
    !Number.isSafeInteger(value.receivedAtEpochSeconds) ||
    value.receivedAtEpochSeconds < 1
  ) {
    throw new TypeError("Invalid Rembrane channel processor message");
  }
  return Object.freeze({ ...value });
}

export function createChannelProcessorAcknowledgement(eventId, status) {
  if (!isBoundedToken(eventId, 256) || !CHANNEL_PROCESSOR_STATUSES.has(status)) {
    throw new TypeError("Invalid Rembrane channel processor acknowledgement");
  }
  return Object.freeze({
    protocolVersion: CHANNEL_PROCESSOR_PROTOCOL_VERSION,
    eventId,
    status,
  });
}

function isExactObject(value, expectedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  return (
    keys.length === expectedKeys.length &&
    keys.every((key, index) => key === expectedKeys[index])
  );
}

function isBoundedToken(value, maximumBytes) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    utf8Length(value) <= maximumBytes &&
    !/[\s\u0000-\u001f\u007f]/u.test(value)
  );
}

function isOpaqueId(value) {
  return (
    typeof value === "string" &&
    utf8Length(value) <= 255 &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)
  );
}

function validateTravelRequestIdentity(request, requireTripId, allowParticipantId) {
  if (
    !isObject(request) ||
    !isOpaqueId(request.workspaceId) ||
    !isOpaqueId(request.subjectId) ||
    (requireTripId && !isOpaqueId(request.tripId)) ||
    (allowParticipantId &&
      request.participantId !== undefined &&
      request.participantId !== null &&
      !isOpaqueId(request.participantId))
  ) {
    throw new TypeError("Travel identity fields must be bounded opaque identifiers");
  }
}

function validateMemoryDiscovery(value, expectedApi) {
  const capabilities = value?.capabilities;
  const limits = value?.limits;
  const privacy = value?.privacy;
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, [
      "provider",
      "protocolVersions",
      "endpoints",
      "capabilities",
      "limits",
      "privacy",
      "extensions",
    ]) ||
    !isObject(value.provider) ||
    !hasOnlyKeys(value.provider, ["id", "name", "implementation"]) ||
    !isBoundedText(value.provider.id, 255) ||
    !isBoundedText(value.provider.name, 255) ||
    (value.provider.implementation !== undefined &&
      (typeof value.provider.implementation !== "string" ||
        utf8Length(value.provider.implementation) > 255)) ||
    !Array.isArray(value.protocolVersions) ||
    value.protocolVersions.length === 0 ||
    new Set(value.protocolVersions).size !== value.protocolVersions.length ||
    !value.protocolVersions.every(
      (version) => typeof version === "string" && /^\d+\.\d+$/u.test(version),
    ) ||
    !isObject(value.endpoints) ||
    !hasOnlyKeys(value.endpoints, [
      "api",
      "oauthAuthorization",
      "oauthToken",
      "mcp",
    ]) ||
    normalizeApiRoot(value.endpoints.api) !== expectedApi ||
    !["oauthAuthorization", "oauthToken"].every(
      (key) =>
        value.endpoints[key] === undefined ||
        isAbsoluteUrl(value.endpoints[key], true),
    ) ||
    (value.endpoints.mcp !== undefined &&
      !isAbsoluteUrl(value.endpoints.mcp, false)) ||
    !isObject(capabilities) ||
    !hasOnlyKeys(capabilities, [
      "contextResolution",
      "questionResolution",
      "memoryProposal",
      "activityCheckpoint",
      "disclosureReceipt",
      "deletionPropagation",
      "sync",
      "imports",
      "exports",
    ]) ||
    ![
      "contextResolution",
      "memoryProposal",
      "activityCheckpoint",
      "disclosureReceipt",
      "deletionPropagation",
    ].every((key) => typeof capabilities[key] === "boolean") ||
    !["questionResolution", "sync"].every(
      (key) => capabilities[key] === undefined || typeof capabilities[key] === "boolean",
    ) ||
    !["imports", "exports"].every(
      (key) =>
        capabilities[key] === undefined ||
        (Array.isArray(capabilities[key]) &&
          new Set(capabilities[key]).size === capabilities[key].length &&
          capabilities[key].every((item) => typeof item === "string")),
    ) ||
    (limits !== undefined &&
      (!isObject(limits) ||
        !hasOnlyKeys(limits, [
          "maximumContextItems",
          "maximumContextBytes",
          "maximumEventBytes",
        ]) ||
        !["maximumContextItems", "maximumContextBytes", "maximumEventBytes"].every(
          (key) =>
            limits[key] === undefined ||
            (Number.isSafeInteger(limits[key]) && limits[key] > 0),
        ))) ||
    !isObject(privacy) ||
    !hasOnlyKeys(privacy, [
      "processingModes",
      "disclosureReceipts",
      "plaintextProcessingLocation",
    ]) ||
    privacy.disclosureReceipts !== true ||
    !Array.isArray(privacy.processingModes) ||
    privacy.processingModes.length === 0 ||
    new Set(privacy.processingModes).size !== privacy.processingModes.length ||
    !privacy.processingModes.every((mode) =>
      DISCOVERY_PROCESSING_MODES.has(mode),
    ) ||
    (privacy.plaintextProcessingLocation !== undefined &&
      !DISCOVERY_PLAINTEXT_LOCATIONS.has(privacy.plaintextProcessingLocation))
    ||
    (value.extensions !== undefined &&
      (!isObject(value.extensions) ||
        !Object.keys(value.extensions).every((key) =>
          /^[a-z0-9][a-z0-9.-]+\/[a-zA-Z0-9._-]+$/u.test(key),
        )))
  ) {
    throw new RembraneError(
      200,
      "invalid_discovery",
      "Provider discovery was invalid or did not match the configured API",
    );
  }
  return value;
}

function hasOnlyKeys(value, allowedKeys) {
  const allowed = new Set(allowedKeys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function isAbsoluteUrl(value, requireHttps) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    const url = new URL(value);
    return Boolean(url.hostname) && (!requireHttps || url.protocol === "https:");
  } catch {
    return false;
  }
}

function normalizeApiRoot(value) {
  if (typeof value !== "string") {
    return null;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1";
  if (
    (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !url.pathname.endsWith("/v1")
  ) {
    return null;
  }
  return url.toString().replace(/\/$/, "");
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedText(value, maximumBytes) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    utf8Length(value) <= maximumBytes
  );
}

function utf8Length(value) {
  return new TextEncoder().encode(value).length;
}
