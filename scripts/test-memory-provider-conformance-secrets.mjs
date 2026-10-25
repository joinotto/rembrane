import assert from "node:assert/strict";
import { chmod, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  resolveConformanceToken,
  resolveLocalSecret,
} from "./memory-provider-conformance-secrets.mjs";

const directory = await mkdtemp(join(tmpdir(), "rembrane-conformance-secret-"));
const protectedFile = join(directory, "token");
await writeFile(protectedFile, "protected-token\r\n", { mode: 0o600 });

assert.equal(
  await resolveConformanceToken("PRIMARY", {
    REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN_REFERENCE: `file:${protectedFile}`,
  }),
  "protected-token",
);
assert.equal(
  await resolveConformanceToken("OTHER", {
    REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN_REFERENCE: "env:OTHER_SECRET",
    OTHER_SECRET: "environment-token",
  }),
  "environment-token",
);
assert.equal(
  await resolveConformanceToken("READONLY", {
    REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN: "legacy-token",
  }),
  "legacy-token",
);

const rejected = async (operation) =>
  assert.rejects(operation, {
    message: "memory-provider conformance credential unavailable",
  });

await rejected(() => resolveLocalSecret("external:vault:key"));
await rejected(() => resolveLocalSecret("env:INVALID-NAME", {}));
await rejected(() => resolveLocalSecret("env:MISSING", {}));

const link = join(directory, "token-link");
await symlink(protectedFile, link);
await rejected(() => resolveLocalSecret(`file:${link}`));

const nullFile = join(directory, "null-token");
await writeFile(nullFile, Buffer.from([0x61, 0x00, 0x62]), { mode: 0o600 });
await rejected(() => resolveLocalSecret(`file:${nullFile}`));

const invalidUtf8 = join(directory, "invalid-utf8");
await writeFile(invalidUtf8, Buffer.from([0xc3, 0x28]), { mode: 0o600 });
await rejected(() => resolveLocalSecret(`file:${invalidUtf8}`));

const oversized = join(directory, "oversized");
await writeFile(oversized, Buffer.alloc(64 * 1024 + 1, 0x61), { mode: 0o600 });
await rejected(() => resolveLocalSecret(`file:${oversized}`));

if (process.platform !== "win32") {
  const exposed = join(directory, "exposed");
  await writeFile(exposed, "exposed-token", { mode: 0o600 });
  await chmod(exposed, 0o644);
  await rejected(() => resolveLocalSecret(`file:${exposed}`));
}

process.stdout.write("memory provider conformance secret resolution verified\n");
