import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  isSafeMemoryProviderBase,
  validateMemoryProviderDiscovery,
} from "./memory-provider-discovery.mjs";

const fixture = JSON.parse(
  await readFile(
    new URL("../spec/examples/memory-provider-discovery.json", import.meta.url),
    "utf8",
  ),
);

assert.equal(validateMemoryProviderDiscovery(fixture), fixture);

for (const invalid of [
  { ...fixture, unexpected: true },
  { ...fixture, privacyMode: "encrypted" },
  { ...fixture, capabilities: [...fixture.capabilities, "unknown_operation"] },
  {
    ...fixture,
    limits: { ...fixture.limits, maximumContextItems: 0 },
  },
  {
    ...fixture,
    operations: fixture.operations.map((operation, index) =>
      index === 0 ? { ...operation, oauthScope: "memory:sync:read" } : operation,
    ),
  },
  {
    ...fixture,
    operations: fixture.operations.slice(1),
  },
  {
    ...fixture,
    operations: [...fixture.operations, fixture.operations[0]],
  },
]) {
  assert.throws(
    () => validateMemoryProviderDiscovery(invalid),
    /not conformance-compatible/,
  );
}

console.log("memory provider discovery validation checks passed");

for (const accepted of [
  "https://memory.example.test",
  "https://memory.example.test:8443/",
  "http://127.0.0.1:8787",
  "http://[::1]:8787/",
]) {
  assert.equal(isSafeMemoryProviderBase(new URL(accepted)), true);
}
for (const rejected of [
  "http://memory.example.test",
  "http://localhost:8787",
  "https://memory.example.test/v1",
  "https://user:secret@memory.example.test",
  "https://memory.example.test?tenant=one",
  "https://memory.example.test#fragment",
]) {
  assert.equal(isSafeMemoryProviderBase(new URL(rejected)), false);
}

console.log("memory provider base URL checks passed");
