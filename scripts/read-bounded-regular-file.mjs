import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { resolve } from "node:path";

export function readBoundedRegularFile(
  input,
  maximum,
  label,
  { allowEmpty = false } = {},
) {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    !Number.isSafeInteger(maximum) ||
    maximum < 1
  ) {
    throw new Error(`${label} must be a bounded regular file`);
  }
  const path = resolve(process.cwd(), input);
  let descriptor;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY |
        (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
    );
    const metadata = fstatSync(descriptor);
    if (
      !metadata.isFile() ||
      (!allowEmpty && metadata.size === 0) ||
      metadata.size > maximum
    ) {
      throw new Error();
    }
    const bytes = readFileSync(descriptor);
    if ((!allowEmpty && bytes.length === 0) || bytes.length > maximum) {
      throw new Error();
    }
    return bytes;
  } catch {
    throw new Error(`${label} must be a bounded regular file`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
