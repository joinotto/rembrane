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
    "rembrane_record_work_trace",
    "rembrane_checkpoint_activity",
    "rembrane_resume_activity",
    "rembrane_create_trip",
    "rembrane_capture_booking_research",
    "rembrane_resolve_travel_context",
    "rembrane_add_trip_participant",
    "rembrane_add_trip_constraint",
    "rembrane_record_trip_decision",
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

  const createdCheckpointCall = await request(9, "tools/call", {
    name: "rembrane_checkpoint_activity",
    arguments: {
      activityId: "activity_e2e",
      entityId: "project_e2e",
      goal: "Build central memory",
      summary: "Encrypted persistence is implemented.",
      nextSteps: ["Run protocol tests"],
      blockers: [],
      stateFingerprint: "git:abc123",
    },
  });
  if (createdCheckpointCall.isError) {
    throw new Error(
      `MCP checkpoint returned an error: ${JSON.stringify(createdCheckpointCall)}`,
    );
  }
  const createdCheckpoint = JSON.parse(
    createdCheckpointCall.content?.find((item) => item.type === "text")?.text,
  );
  if (createdCheckpoint.version !== 1) {
    throw new Error("MCP checkpoint did not create version 1");
  }

  const firstResumeCall = await request(10, "tools/call", {
    name: "rembrane_resume_activity",
    arguments: {
      activityId: "activity_e2e",
      currentStateFingerprint: "git:abc123",
    },
  });
  const firstCheckpoint = JSON.parse(
    firstResumeCall.content?.find((item) => item.type === "text")?.text,
  );
  if (firstCheckpoint.summary !== "Encrypted persistence is implemented.") {
    throw new Error("MCP resume did not return the checkpoint");
  }
  if (firstCheckpoint.stale !== false) {
    throw new Error("MCP marked matching external state as stale");
  }
  if (!firstCheckpoint.disclosureId) {
    throw new Error("MCP checkpoint resume omitted disclosureId");
  }

  const updatedCheckpointCall = await request(11, "tools/call", {
    name: "rembrane_checkpoint_activity",
    arguments: {
      activityId: "activity_e2e",
      expectedVersion: 1,
      summary: "Protocol smoke tests are implemented.",
      nextSteps: ["Run the full suite"],
      blockers: [],
      stateFingerprint: "git:def456",
    },
  });
  const updatedCheckpoint = JSON.parse(
    updatedCheckpointCall.content?.find((item) => item.type === "text")?.text,
  );
  if (updatedCheckpoint.version !== 2) {
    throw new Error("MCP checkpoint did not update to version 2");
  }

  const finalResumeCall = await request(12, "tools/call", {
    name: "rembrane_resume_activity",
    arguments: {
      activityId: "activity_e2e",
      currentStateFingerprint: "git:abc123",
    },
  });
  const finalCheckpoint = JSON.parse(
    finalResumeCall.content?.find((item) => item.type === "text")?.text,
  );
  if (finalCheckpoint.summary !== "Protocol smoke tests are implemented.") {
    throw new Error("MCP resume did not return the updated checkpoint");
  }
  if (finalCheckpoint.stale !== true) {
    throw new Error("MCP did not detect stale external state");
  }
  if (
    !finalCheckpoint.disclosureId ||
    finalCheckpoint.disclosureId === firstCheckpoint.disclosureId
  ) {
    throw new Error("MCP checkpoint resume reused its disclosure receipt");
  }

  const workTraceCall = await request(13, "tools/call", {
    name: "rembrane_record_work_trace",
    arguments: {
      activityId: "activity_e2e",
      entityId: "project_e2e",
      summary: "Ran the MCP lifecycle and stale-state checks.",
    },
  });
  if (workTraceCall.isError) {
    throw new Error(
      `MCP work trace returned an error: ${JSON.stringify(workTraceCall)}`,
    );
  }
  const workTrace = JSON.parse(
    workTraceCall.content?.find((item) => item.type === "text")?.text,
  );
  if (workTrace.status !== "proposed" || !workTrace.memoryId) {
    throw new Error("MCP work trace was not recorded as proposed memory");
  }

  const deniedResumeCall = await request(14, "tools/call", {
    name: "rembrane_resume_activity",
    arguments: {
      activityId: "activity_outside_grant",
    },
  });
  if (!deniedResumeCall.isError) {
    throw new Error("MCP allowed activity access outside the connection grant");
  }

  const missingTripResearchCall = await request(15, "tools/call", {
    name: "rembrane_capture_booking_research",
    arguments: {
      tripId: "trip_missing",
      kind: "flight",
      provider: "e2e-search",
      summary: "Nonstop morning option",
      sourceReference: "opaque-result-e2e",
      evidenceSource: "tool-result",
      observedAt: "2026-10-25T10:00:00Z",
      expiresAt: "2026-10-25T10:30:00Z",
    },
  });
  if (!missingTripResearchCall.isError) {
    throw new Error("MCP captured booking research for a missing canonical trip");
  }

  const createdTripCall = await request(16, "tools/call", {
    name: "rembrane_create_trip",
    arguments: {
      title: "Kyoto continuity test",
      origin: "Bengaluru",
      destinations: ["Kyoto"],
      departNotBefore: "2026-11-01",
      returnNotAfter: "2026-11-12",
    },
  });
  if (createdTripCall.isError) {
    throw new Error(
      `MCP trip creation returned an error: ${JSON.stringify(createdTripCall)}`,
    );
  }
  const createdTrip = JSON.parse(
    createdTripCall.content?.find((item) => item.type === "text")?.text,
  );
  if (!createdTrip.tripId || createdTrip.version !== 1) {
    throw new Error("MCP trip creation returned invalid metadata");
  }

  const participantCall = await request(17, "tools/call", {
    name: "rembrane_add_trip_participant",
    arguments: {
      tripId: createdTrip.tripId,
      label: "Hippo",
      expectedTripVersion: 1,
    },
  });
  if (participantCall.isError) {
    throw new Error(
      `MCP participant mutation failed: ${JSON.stringify(participantCall)}`,
    );
  }
  const participant = JSON.parse(
    participantCall.content?.find((item) => item.type === "text")?.text,
  );
  if (!participant.participantId || participant.tripVersion !== 2) {
    throw new Error("MCP participant mutation returned invalid metadata");
  }

  const constraintCall = await request(18, "tools/call", {
    name: "rembrane_add_trip_constraint",
    arguments: {
      tripId: createdTrip.tripId,
      participantId: participant.participantId,
      kind: "dietary",
      statement: "Vegetarian meals",
      evidenceSource: "user-statement",
      expectedTripVersion: 2,
    },
  });
  if (constraintCall.isError) {
    throw new Error(`MCP constraint mutation failed: ${JSON.stringify(constraintCall)}`);
  }
  const constraint = JSON.parse(
    constraintCall.content?.find((item) => item.type === "text")?.text,
  );
  if (!constraint.recordId || constraint.tripVersion !== 3) {
    throw new Error("MCP constraint mutation returned invalid metadata");
  }

  const decisionCall = await request(19, "tools/call", {
    name: "rembrane_record_trip_decision",
    arguments: {
      tripId: createdTrip.tripId,
      status: "selected",
      summary: "Prefer the nonstop flight",
      rationale: "Simpler handoff",
      evidenceSource: "workspace-decision",
      expectedTripVersion: 3,
    },
  });
  if (decisionCall.isError) {
    throw new Error(`MCP decision mutation failed: ${JSON.stringify(decisionCall)}`);
  }
  const decision = JSON.parse(
    decisionCall.content?.find((item) => item.type === "text")?.text,
  );
  if (!decision.recordId || decision.tripVersion !== 4) {
    throw new Error("MCP decision mutation returned invalid metadata");
  }

  const capturedResearchCall = await request(20, "tools/call", {
    name: "rembrane_capture_booking_research",
    arguments: {
      tripId: createdTrip.tripId,
      kind: "flight",
      provider: "e2e-search",
      summary: "Nonstop morning option",
      sourceReference: "opaque-result-success",
      evidenceSource: "tool-result",
      observedAt: "2026-10-25T10:00:00Z",
      expiresAt: "2026-10-25T10:30:00Z",
    },
  });
  if (capturedResearchCall.isError) {
    throw new Error(
      `MCP research capture returned an error: ${JSON.stringify(capturedResearchCall)}`,
    );
  }
  const capturedResearch = JSON.parse(
    capturedResearchCall.content?.find((item) => item.type === "text")?.text,
  );
  if (
    !capturedResearch.researchId ||
    capturedResearch.tripId !== createdTrip.tripId ||
    capturedResearch.version !== 1
  ) {
    throw new Error("MCP research capture returned invalid metadata");
  }

  const travelContextCall = await request(21, "tools/call", {
    name: "rembrane_resolve_travel_context",
    arguments: {
      tripId: createdTrip.tripId,
      purpose: "continue flight planning in another assistant",
      asOf: "2026-10-25T10:15:00Z",
    },
  });
  if (travelContextCall.isError) {
    throw new Error(
      `MCP travel context returned an error: ${JSON.stringify(travelContextCall)}`,
    );
  }
  const travelContext = JSON.parse(
    travelContextCall.content?.find((item) => item.type === "text")?.text,
  );
  if (
    !travelContext.disclosureId ||
    travelContext.trip?.tripId !== createdTrip.tripId ||
    travelContext.freshResearch?.length !== 1 ||
    travelContext.expiredResearch?.length !== 0
  ) {
    throw new Error("MCP travel context returned invalid continuity data");
  }
  if ("sourceReference" in travelContext.freshResearch[0]) {
    throw new Error("MCP travel context exposed an opaque source reference");
  }

  const deniedSensitiveContextCall = await request(22, "tools/call", {
    name: "rembrane_resolve_travel_context",
    arguments: {
      tripId: createdTrip.tripId,
      purpose: "reopen the provider result",
      asOf: "2026-10-25T10:15:00Z",
      includeSourceReferences: true,
    },
  });
  if (!deniedSensitiveContextCall.isError) {
    throw new Error(
      "MCP revealed a source reference without connection-level permission",
    );
  }
} finally {
  child.kill("SIGTERM");
  await new Promise((resolve) => {
    child.once("exit", resolve);
    setTimeout(resolve, 2_000);
  });
}

console.log("MCP protocol checks passed");
