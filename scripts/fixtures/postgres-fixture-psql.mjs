#!/usr/bin/env node
import { appendFileSync } from "node:fs";

// A guard-test double, never a database/RLS proof. Stop at the first migration.
const args = process.argv.slice(2);
const probe = args.includes("-c");
appendFileSync(
  process.env.REMBRANE_FIXTURE_CALL_LOG,
  `${JSON.stringify({
    args,
    service: process.env.PGSERVICE,
    serviceFile: process.env.PGSERVICEFILE,
    probe,
  })}\n`,
);
if (!probe || process.env.REMBRANE_FIXTURE_PROOF === "fail") {
  console.log("fixture-secret-must-not-leak");
  console.error("fixture-secret-must-not-leak");
  process.exit(90);
}
console.log(process.env.REMBRANE_FIXTURE_PROOF);
