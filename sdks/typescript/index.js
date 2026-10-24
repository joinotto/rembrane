const DEFAULT_MAXIMUM_RESPONSE_BYTES = 1024 * 1024;

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

  rotateWorkspaceKey(request) {
    return this.#request("POST", "/workspaces/key-rotation", request);
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
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method,
      redirect: "error",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${this.#token}`,
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
