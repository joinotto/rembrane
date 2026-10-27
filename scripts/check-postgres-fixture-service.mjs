import { constants, closeSync, fstatSync, openSync } from "node:fs";
import { isAbsolute } from "node:path";

// Validate metadata without printing or parsing credentials. libpq remains
// responsible for the service-file format. The operator must keep this private
// file and the disposable database under exclusive control during the test.
let descriptor;
try {
  const path = process.argv[2];
  if (!path || !isAbsolute(path) || process.platform === "win32") throw Error();
  descriptor = openSync(
    path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  const metadata = fstatSync(descriptor);
  if (
    !metadata.isFile() ||
    metadata.size === 0 ||
    metadata.size > 65_536 ||
    metadata.uid !== process.getuid() ||
    ![0o400, 0o600].includes(metadata.mode & 0o777)
  ) {
    throw Error();
  }
} catch {
  console.error("PostgreSQL fixture service must be a private caller-owned regular file");
  process.exitCode = 2;
} finally {
  if (descriptor !== undefined) closeSync(descriptor);
}
