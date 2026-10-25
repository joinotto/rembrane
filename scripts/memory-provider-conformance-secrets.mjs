import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { resolve } from "node:path";

const maximumSecretBytes = 64 * 1024;
const opaqueError = "memory-provider conformance credential unavailable";

export async function resolveConformanceToken(role, environment = process.env) {
  if (!/^(PRIMARY|OTHER|READONLY)$/.test(role)) throw new Error(opaqueError);
  const prefix = `REMBRANE_MEMORY_PROVIDER_${role}_TOKEN`;
  const reference = environment[`${prefix}_REFERENCE`];
  if (reference !== undefined && reference !== "") {
    return resolveLocalSecret(reference, environment);
  }
  return validateSecret(environment[prefix]);
}

export async function resolveLocalSecret(reference, environment = process.env) {
  try {
    if (
      typeof reference !== "string" ||
      reference.length === 0 ||
      reference.length > 8192 ||
      /[\0\r\n]/u.test(reference)
    ) {
      throw new Error();
    }
    if (reference.startsWith("env:")) {
      const name = reference.slice(4);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) throw new Error();
      return validateSecret(environment[name]);
    }
    if (reference.startsWith("file:")) {
      const name = reference.slice(5);
      if (name.length === 0) throw new Error();
      const path = resolve(name);
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error();
      const handle = await open(
        path,
        constants.O_RDONLY |
          (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
      );
      let bytes;
      try {
        const openedMetadata = await handle.stat();
        if (!openedMetadata.isFile()) throw new Error();
        if (
          process.platform !== "win32" &&
          (openedMetadata.mode & 0o077) !== 0
        ) {
          throw new Error();
        }
        if (
          openedMetadata.size === 0 ||
          openedMetadata.size > maximumSecretBytes
        ) {
          throw new Error();
        }
        bytes = await handle.readFile();
      } finally {
        await handle.close();
      }
      if (bytes.length === 0 || bytes.length > maximumSecretBytes) {
        throw new Error();
      }
      const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      return validateSecret(
        value.endsWith("\r\n")
          ? value.slice(0, -2)
          : value.endsWith("\n")
            ? value.slice(0, -1)
            : value,
      );
    }
    throw new Error();
  } catch {
    throw new Error(opaqueError);
  }
}

function validateSecret(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > maximumSecretBytes ||
    value.includes("\0")
  ) {
    throw new Error(opaqueError);
  }
  return value;
}
