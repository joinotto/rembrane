#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";

// A readiness-check double only. It does not compile Rust or contact a server.
const args = process.argv.slice(2);
appendFileSync(process.env.REMBRANE_RUNTIME_GATE_CALL_LOG, `${JSON.stringify(args)}\n`);
const scenario = JSON.parse(readFileSync(process.env.REMBRANE_RUNTIME_GATE_SCENARIO, "utf8"));
if (args[0] === "metadata") {
  console.log(scenario.metadata ?? "not-json");
  process.exit(scenario.metadataStatus ?? 0);
}
if (args[0] === "check") {
  if (scenario.buildStatus) console.error("runtime-gate-secret-must-not-leak");
  process.exit(scenario.buildStatus ?? 0);
}
if (args[0] !== "test") process.exit(99);
const count = args[args.indexOf("--") + 1] === scenario.failTest ? 0 : 1;
console.error("runtime-gate-secret-must-not-leak");
console.log(scenario.testOutput ?? `test result: ok. ${count} passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.25s\n`);
process.exit(scenario.testStatus ?? 0);
