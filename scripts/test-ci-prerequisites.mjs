import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const workflow = fileURLToPath(new URL("../.github/workflows/ci.yml", import.meta.url));
const parsed = spawnSync("ruby", [
  "-ryaml", "-rjson", "-e", "puts JSON.generate(YAML.load_file(ARGV.fetch(0)))",
  workflow,
], { encoding: "utf8", timeout: 10_000 });
assert.equal(parsed.error, undefined);
assert.equal(parsed.status, 0, parsed.stderr);
const jobs = JSON.parse(parsed.stdout).jobs;
const requirements = {
  static: ["ripgrep", "jq", "sqlite3", "ruby", "openssl", "curl", "python3"],
  rust: ["ripgrep", "jq", "sqlite3", "ruby", "openssl", "curl", "python3"],
  "memory-provider-http": ["ripgrep", "jq", "openssl", "curl"],
  "kotlin-sdk": ["ripgrep"],
};

function validate(name, steps) {
  const testIndex = steps.findIndex((step) =>
    typeof step.run === "string" &&
    /(?:check-local-alpha\.sh|test-memory-provider-http-runner\.mjs|test-kotlin-sdk\.sh)/.test(step.run),
  );
  assert.ok(testIndex >= 0, `${name}: executable tests required`);
  const beforeTests = steps.slice(0, testIndex);
  const installed = beforeTests.flatMap((step) => {
    const match = step.run?.match(/sudo apt-get install --yes ([a-z0-9 -]+)(?:\n|$)/);
    return match ? match[1].trim().split(/\s+/) : [];
  });
  for (const dependency of requirements[name]) {
    assert.ok(installed.includes(dependency), `${name}: install ${dependency} before tests`);
  }
  if (name !== "kotlin-sdk") {
    assert.ok(beforeTests.some((step) =>
      step.uses === "actions/setup-node@v4" && String(step.with?.["node-version"]) === "22",
    ), `${name}: select Node 22 before tests`);
  }
}

for (const name of Object.keys(requirements)) {
  validate(name, jobs[name].steps);
  const withoutInstall = jobs[name].steps.filter((step) =>
    !step.run?.includes("sudo apt-get install"),
  );
  assert.throws(() => validate(name, withoutInstall), /install ripgrep/);
  if (name !== "kotlin-sdk") {
    const withoutNode = jobs[name].steps.filter((step) =>
      step.uses !== "actions/setup-node@v4",
    );
    assert.throws(() => validate(name, withoutNode), /select Node 22/);
  }
}
console.log("CI prerequisite declarations and seven refusal cases passed");
