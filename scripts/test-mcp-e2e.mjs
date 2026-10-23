import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const binary = process.env.REMBRANE_MCP_BIN;
if (!binary) {
  throw new Error("REMBRANE_MCP_BIN is required");
}

const child = spawn(binary, [], {
  env: process.env,
  stdio: ["pipe", "pipe", "pipe"],
});
const lines = createInterface({ input: child.stdout });
const pending = new Map();
let stderr = "";

child.stderr.setEncoding("utf8");
child.stderr.on("data", (chunk) => {
  stderr += chunk;
});

lines.on("line", (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    fail(new Error("MCP stdout contained a non-JSON protocol line"));
    return;
  }
  if (message.id !== undefined && pending.has(message.id)) {
    const { resolve, reject, timer } = pending.get(message.id);
    clearTimeout(timer);
    pending.delete(message.id);
    if (message.error) {
      reject(new Error(`MCP request failed: ${JSON.stringify(message.error)}`));
    } else {
      resolve(message.result);
    }
  }
});

child.on("exit", (code, signal) => {
  if (pending.size > 0) {
    fail(
      new Error(
        `MCP server exited early (${code ?? signal}): ${stderr.slice(0, 500)}`,
      ),
    );
  }
});

function send(message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

function request(id, method, params) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`MCP request timed out: ${method}`));
    }, 10_000);
    pending.set(id, { resolve, reject, timer });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

function fail(error) {
  child.kill("SIGTERM");
  throw error;
}

try {
  const initialization = await request(1, "initialize", {
    protocolVersion: "2026-07-28",
    capabilities: {},
    clientInfo: {
      name: "rembrane-e2e",
      version: "0.1.0",
    },
  });
  if (!initialization.serverInfo?.name) {
    throw new Error("MCP initialize response omitted serverInfo");
  }

  send({
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
  });

  const tools = await request(2, "tools/list", {});
  const toolNames = new Set(tools.tools?.map((tool) => tool.name));
  for (const expected of [
    "rembrane_resolve_context",
    "rembrane_remember_preference",
    "rembrane_request_correction",
    "rembrane_forget_memory",
  ]) {
    if (!toolNames.has(expected)) {
      throw new Error(`MCP tool list omitted ${expected}`);
    }
  }

  const rememberedCall = await request(3, "tools/call", {
    name: "rembrane_remember_preference",
    arguments: {
      content: "Call me Hippo",
    },
  });
  if (rememberedCall.isError) {
    throw new Error(
      `MCP remember returned an error: ${JSON.stringify(rememberedCall)}`,
    );
  }
  const remembered = JSON.parse(
    rememberedCall.content?.find((item) => item.type === "text")?.text,
  );
  if (!remembered.memoryId || remembered.version !== 1) {
    throw new Error("MCP remember returned invalid memory metadata");
  }

  const firstResolve = await request(4, "tools/call", {
    name: "rembrane_resolve_context",
    arguments: {
      purpose: "personalize-assistant",
      query: "What should I call the user?",
      maximumItems: 10,
    },
  });
  if (firstResolve.isError) {
    throw new Error(
      `MCP resolve returned an error: ${JSON.stringify(firstResolve)}`,
    );
  }
  const text = firstResolve.content?.find((item) => item.type === "text")?.text;
  const context = JSON.parse(text);
  if (context.items?.length !== 1) {
    throw new Error("MCP context did not contain exactly one memory");
  }
  if (context.items[0].content !== "Call me Hippo") {
    throw new Error("MCP context contained unexpected memory content");
  }
  if (!context.disclosureId) {
    throw new Error("MCP context omitted disclosureId");
  }

  const correctedCall = await request(5, "tools/call", {
    name: "rembrane_request_correction",
    arguments: {
      memoryId: remembered.memoryId,
      expectedVersion: 1,
      replacement: "Call me Captain Hippo",
    },
  });
  if (correctedCall.isError) {
    throw new Error(
      `MCP correction returned an error: ${JSON.stringify(correctedCall)}`,
    );
  }
  const corrected = JSON.parse(
    correctedCall.content?.find((item) => item.type === "text")?.text,
  );
  if (corrected.version !== 2) {
    throw new Error("MCP correction did not create version 2");
  }

  const secondResolve = await request(6, "tools/call", {
    name: "rembrane_resolve_context",
    arguments: {
      purpose: "personalize-assistant",
      query: "What should I call the user?",
      maximumItems: 10,
    },
  });
  const secondContext = JSON.parse(
    secondResolve.content?.find((item) => item.type === "text")?.text,
  );
  if (secondContext.items?.[0]?.content !== "Call me Captain Hippo") {
    throw new Error("MCP resolve did not return corrected memory");
  }

  const forgottenCall = await request(7, "tools/call", {
    name: "rembrane_forget_memory",
    arguments: {
      memoryId: remembered.memoryId,
      expectedVersion: 2,
      reason: "User requested deletion",
    },
  });
  if (forgottenCall.isError) {
    throw new Error(
      `MCP forget returned an error: ${JSON.stringify(forgottenCall)}`,
    );
  }

  const finalResolve = await request(8, "tools/call", {
    name: "rembrane_resolve_context",
    arguments: {
      purpose: "personalize-assistant",
      query: "What should I call the user?",
      maximumItems: 10,
    },
  });
  const finalContext = JSON.parse(
    finalResolve.content?.find((item) => item.type === "text")?.text,
  );
  if (finalContext.items?.length !== 0) {
    throw new Error("MCP resolve disclosed a deleted memory");
  }
} finally {
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    child.once("exit", resolve);
    setTimeout(resolve, 2_000);
  });
}

console.log("MCP protocol checks passed");
