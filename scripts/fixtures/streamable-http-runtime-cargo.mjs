#!/usr/bin/env node
// Fake process output tests gate behavior only, not Rust or SDK correctness.
import { appendFileSync, readFileSync } from "node:fs";

const args = process.argv.slice(2);
appendFileSync(process.env.REMBRANE_MCP_RUNTIME_GATE_CALL_LOG, `${JSON.stringify(args)}\n`);
const scenario = JSON.parse(readFileSync(process.env.REMBRANE_MCP_RUNTIME_GATE_SCENARIO, "utf8"));
const secret = "mcp-runtime-gate-secret-must-not-leak";
if (args[0] === "metadata") {
  console.error(secret);
  console.log(scenario.metadata);
  process.exit(scenario.metadataStatus ?? 0);
}
if (args[0] === "check") {
  console.error(secret);
  const status = args.includes("--bin") ? scenario.binaryStatus : scenario.testBuildStatus;
  process.exit(status ?? 0);
}
if (args[0] === "test") {
  console.error(secret);
  const name = args[args.indexOf("--") + 1];
  const passes = name === scenario.failTest ? 0 : 1;
  console.log(scenario.testOutput
    ?? `test result: ok. ${passes} passed; 0 failed; 0 ignored; 0 measured; 7 filtered out; finished in 0.00s`);
  process.exit(scenario.testStatus ?? 0);
}
process.exit(1);
