# Secret resolution

Rembrane configuration stores validated references, never credential values.
Applications resolve those references inside the deployment that owns the
credentials and pass only short-lived values to the selected adapter.

`rembrane-secret-local` defines the replaceable `SecretResolver` boundary and
provides `LocalSecretResolver` for:

- process environment variables;
- protected regular files such as Docker or Kubernetes secret mounts.

Resolved strings are held in zeroizing memory and limited to 64 KiB. File
resolution rejects symbolic links, non-regular files, empty or invalid UTF-8
values, null bytes, and oversized content. On Unix, group or other permission
bits are rejected. One final LF or CRLF written by a secret-mount mechanism is
removed; all other bytes remain unchanged.

External references deliberately return `UnsupportedSource` from the local
resolver. A deployment integrates Vault, AWS Secrets Manager, Azure Key Vault,
Google Secret Manager, an OS keychain, or another system by implementing
`SecretResolver`. The implementation must:

- authenticate through deployment-owned identity;
- return `Zeroizing<String>`;
- enforce its own response and timeout bounds;
- avoid logs, metrics, traces, command arguments, and error text containing
  either the reference key or resolved value;
- fetch directly from the user's environment without a Rembrane-operated
  credential relay.

The resolver port does not cache values. Rotation can therefore take effect on
the next application-owned resolution without rebuilding Rembrane.
