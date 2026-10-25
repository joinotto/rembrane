import { createHash } from "node:crypto";

import { readBoundedRegularFile } from "./read-bounded-regular-file.mjs";

const [input, maximumInput] = process.argv.slice(2);
const maximum = Number(maximumInput);
if (
  !input ||
  !/^[1-9][0-9]*$/.test(maximumInput ?? "") ||
  !Number.isSafeInteger(maximum) ||
  process.argv.length !== 4
) {
  throw new Error(
    "usage: sha256-bounded-file.mjs INPUT MAXIMUM_BYTES",
  );
}
process.stdout.write(
  createHash("sha256")
    .update(readBoundedRegularFile(input, maximum, "hash input"))
    .digest("hex"),
);
