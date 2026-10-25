import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const binary = process.env.REMBRANE_MCP_BIN;
const memoryId = process.env.REMBRANE_HANDOFF_MEMORY_ID;
if (!binary || !memoryId) {
  throw new Error(
    "REMBRANE_MCP_BIN and REMBRANE_HANDOFF_MEMORY_ID are required",
  );
}

function startClient(clientId) {
  const child = spawn(binary, [], {
    env: { ...process.env, REMBRANE_CLIENT_ID: clientId },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const lines = createInterface({ input: child.stdout });
  const pending = new Map();
  let nextId = 1;
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
      child.kill("SIGTERM");
      throw new Error("MCP stdout contained a non-JSON protocol line");
    }
    const request = pending.get(message.id);
    if (!request) {
      return;
    }
    clearTimeout(request.timer);
    pending.delete(message.id);
    if (message.error) {
      request.reject(
        new Error(`MCP request failed: ${JSON.stringify(message.error)}`),
      );
    } else {
      request.resolve(message.result);
    }
  });
  child.on("exit", (code, signal) => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(
        new Error(
          `MCP server exited early (${code ?? signal}): ${stderr.slice(0, 500)}`,
        ),
      );
    }
    pending.clear();
  });

  function send(message) {
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  function request(method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`MCP request timed out: ${method}`));
      }, 10_000);
      pending.set(id, { resolve, reject, timer });
      send({ jsonrpc: "2.0", id, method, params });
    });
  }

  async function initialize() {
    await request("initialize", {
      protocolVersion: "2026-07-28",
      capabilities: {},
      clientInfo: { name: clientId, version: "0.1.0" },
    });
    send({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    });
  }

  async function callTool(name, args) {
    const result = await request("tools/call", { name, arguments: args });
    if (result.isError) {
      throw new Error(`${name} returned an error: ${JSON.stringify(result)}`);
    }
    const text = result.content?.find((item) => item.type === "text")?.text;
    return JSON.parse(text);
  }

  async function close() {
    child.stdin.end();
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill("SIGTERM");
        reject(
          new Error(
            `MCP server did not exit cleanly: ${stderr.slice(0, 500)}`,
          ),
        );
      }, 5_000);
      child.once("exit", (code) => {
        clearTimeout(timer);
        if (code === 0 || code === null) {
          resolve();
        } else {
          reject(
            new Error(
              `MCP server exited with code ${code}: ${stderr.slice(0, 500)}`,
            ),
          );
        }
      });
    });
  }

  return { initialize, callTool, close };
}

const firstClient = startClient("client_handoff_writer");
await firstClient.initialize();

const context = await firstClient.callTool("rembrane_resolve_context", {
  purpose: "continue-user-preferences",
  query: "What should I call the user?",
  maximumItems: 10,
});
if (
  context.items?.length !== 1 ||
  context.items[0].content !== "Call me Hippo" ||
  !context.disclosureId
) {
  throw new Error("MCP client did not receive the preference written by CLI");
}

const correction = await firstClient.callTool("rembrane_request_correction", {
  memoryId,
  expectedVersion: 1,
  replacement: "Call me Captain Hippo",
});
if (correction.version !== 2) {
  throw new Error("MCP client did not create preference version 2");
}

const checkpoint = await firstClient.callTool("rembrane_checkpoint_activity", {
  activityId: "activity_handoff",
  entityId: "project_handoff",
  goal: "Ship cross-tool memory continuity",
  summary: "CLI and the first MCP client share encrypted memory.",
  nextSteps: ["Resume from a fresh agent process"],
  blockers: [],
  stateFingerprint: "git:handoff123",
});
if (checkpoint.version !== 1) {
  throw new Error("MCP client did not create checkpoint version 1");
}
await firstClient.close();

const secondClient = startClient("client_handoff_reader");
await secondClient.initialize();
const resumed = await secondClient.callTool("rembrane_resume_activity", {
  activityId: "activity_handoff",
  currentStateFingerprint: "git:handoff123",
});
if (
  resumed.summary !== "CLI and the first MCP client share encrypted memory." ||
  resumed.stale !== false ||
  !resumed.disclosureId
) {
  throw new Error("fresh MCP client did not resume the prior agent checkpoint");
}
await secondClient.close();
