import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  RembraneClient,
  RembraneError,
  createChannelProcessorAcknowledgement,
  parseChannelProcessorMessage,
} from "./index.js";

const calls = [];
const client = new RembraneClient({
  baseUrl: "http://127.0.0.1:8787/v1",
  token: "test-token",
  fetch: async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      headers: { get: () => "application/json; charset=utf-8" },
      text: async () => '{"events":[]}',
    };
  },
});

await client.listAdministrativeAudit({
  workspaceId: "team",
  afterEpochSeconds: 10,
  limit: 20,
});
assert.equal(
  calls[0].url,
  "http://127.0.0.1:8787/v1/administrative-audit?workspaceId=team&afterEpochSeconds=10&limit=20",
);
assert.equal(calls[0].init.headers.Authorization, "Bearer test-token");
assert.equal(calls[0].init.redirect, "error");

const createInvitation = {
  workspaceId: "team",
  invitationId: "invite-1",
  invitedPrincipalId: "principal-2",
  role: "member",
  ttlSeconds: 3600,
  requestId: "request-1",
};
const transitionInvitation = {
  workspaceId: "team",
  invitationId: "invite-1",
  requestId: "request-2",
};
await client.createWorkspaceInvitation(createInvitation);
await client.acceptWorkspaceInvitation(transitionInvitation);
await client.revokeWorkspaceInvitation({
  ...transitionInvitation,
  requestId: "request-3",
});
await client.listWorkspaceInvitations({
  workspaceId: "team/name",
  status: "accepted",
  limit: 20,
});

for (const [index, path] of [
  [1, "/workspaces/invitations"],
  [2, "/workspaces/invitations/accept"],
  [3, "/workspaces/invitations/revoke"],
]) {
  assert.equal(calls[index].url, `http://127.0.0.1:8787/v1${path}`);
  assert.equal(calls[index].init.method, "POST");
  assert.equal(calls[index].init.headers.Authorization, "Bearer test-token");
  assert.equal(calls[index].init.headers["Content-Type"], "application/json");
}
assert.deepEqual(JSON.parse(calls[1].init.body), createInvitation);
assert.deepEqual(JSON.parse(calls[2].init.body), transitionInvitation);
assert.deepEqual(JSON.parse(calls[3].init.body), {
  ...transitionInvitation,
  requestId: "request-3",
});
assert.equal(
  calls[4].url,
  "http://127.0.0.1:8787/v1/workspaces/invitations?workspaceId=team%2Fname&status=accepted&limit=20",
);
assert.equal(calls[4].init.method, "GET");
assert.equal(calls[4].init.headers.Authorization, "Bearer test-token");
assert.equal(calls[4].init.body, undefined);

const graphRequest = {
  workspaceId: "team",
  subjectId: "principal-1",
  nodeId: "project-1",
  direction: "outgoing",
  validAtEpochSeconds: 1_700_000_000,
  maximumCandidates: 20,
  purpose: "continue-project",
  entityId: "project-1",
};
await client.resolveGraphContext(graphRequest);
assert.equal(calls[5].url, "http://127.0.0.1:8787/v1/graph/context/resolve");
assert.equal(calls[5].init.method, "POST");
assert.equal(calls[5].init.headers.Authorization, "Bearer test-token");
assert.deepEqual(JSON.parse(calls[5].init.body), graphRequest);

assert.throws(
  () =>
    new RembraneClient({
      baseUrl: "http://memory.example.test/v1",
      token: "token",
      fetch: async () => {},
    }),
  /HTTPS or an explicit loopback URL/,
);

const failing = new RembraneClient({
  baseUrl: "https://memory.example.test/v1",
  token: "token",
  fetch: async () => ({
    ok: false,
    status: 403,
    headers: { get: () => "application/json" },
    text: async () => '{"code":"access_denied","message":"Access denied"}',
  }),
});
await assert.rejects(
  failing.rotateWorkspaceKey({ workspaceId: "team" }),
  (error) =>
    error instanceof RembraneError &&
    error.status === 403 &&
    error.code === "access_denied",
);

const channelFixture = JSON.parse(
  await readFile(
    new URL("../../spec/examples/channel-processor-message.json", import.meta.url),
    "utf8",
  ),
);
const parsedChannelMessage = parseChannelProcessorMessage(channelFixture);
assert.deepEqual(parsedChannelMessage, channelFixture);
assert.equal(Object.isFrozen(parsedChannelMessage), true);

const acknowledgement = createChannelProcessorAcknowledgement(
  channelFixture.eventId,
  "processed",
);
const acknowledgementFixture = JSON.parse(
  await readFile(
    new URL(
      "../../spec/examples/channel-processor-acknowledgement.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
assert.deepEqual(acknowledgement, acknowledgementFixture);
assert.equal(Object.isFrozen(acknowledgement), true);

for (const invalid of [
  null,
  { ...channelFixture, protocolVersion: "0.2" },
  { ...channelFixture, channel: "sms" },
  { ...channelFixture, eventId: "unsafe event" },
  { ...channelFixture, workspaceId: "x".repeat(256) },
  { ...channelFixture, text: " \n\t" },
  { ...channelFixture, text: "😀".repeat(4_097) },
  { ...channelFixture, receivedAtEpochSeconds: 0 },
  { ...channelFixture, ignored: true },
]) {
  assert.throws(
    () => parseChannelProcessorMessage(invalid),
    /Invalid Rembrane channel processor message/,
  );
}
assert.throws(
  () =>
    createChannelProcessorAcknowledgement(channelFixture.eventId, "accepted"),
  /Invalid Rembrane channel processor acknowledgement/,
);
