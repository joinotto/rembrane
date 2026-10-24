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

`resolve_provider_credentials` consumes a validated provider profile's
duplicate-free ordered reference list through any `SecretResolver`. If one
lookup fails, previously resolved values from that attempt are dropped through
their zeroization guards and no partial credential set is returned.

`HttpIntrospectionTransport::from_config` resolves the OAuth client-secret
reference from a validated remote MCP profile through the same boundary. The
resolved value remains zeroizing through validation, HTTP-client construction,
use, and teardown; resolver failures are mapped to an opaque transport error.

`ConfiguredGraphProvider::from_connection` applies the same pattern to a
validated Graphiti provider profile. It checks provider kind, credential
cardinality, and the explicit plaintext-processing policy before resolving the
bearer credential, then transfers the zeroizing value directly into the HTTP
transport.

`ConfiguredMemoryProvider::from_connection` consumes validated Mem0 or
Supermemory profiles through the resolver boundary. It validates provider
kind, credential cardinality, and request identity before resolution, moves
the zeroizing bearer value directly into the portable HTTP client, and still
requires provider discovery to satisfy the caller's explicit privacy policy.

`ConfiguredRecordCipher::from_connection` consumes a validated key-provider
profile with one credential reference. The resolved value remains zeroizing
through transport validation, protocol negotiation, record encryption and
decryption operations, and teardown.
Its environment-driven HTTP composition accepts
`REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE` with the same local locator semantics
and retains the resolved credential in `Zeroizing<String>` throughout
configuration handoff. The shipped channel Compose overlays intentionally
forward only this locator, never `REMBRANE_KEY_PROVIDER_TOKEN`. A deployment
using the HTTP provider must mount the credential into the service's private
runtime secret directory and set a `file:/run/rembrane-secrets/...` locator,
or supply an equivalent protected resolver in its own overlay.

The local development cipher accepts `REMBRANE_WORKSPACE_KEY_REFERENCE` and
defaults to `env:REMBRANE_WORKSPACE_KEY_HEX` for compatibility. A protected
`file:path` value is resolved into zeroizing storage, decoded, and dropped
before the active cipher enters service. Stock Compose uses this path so raw
workspace keys are absent from container environment metadata.

Because local Compose implementations may not honor requested ownership and
mode metadata for file-backed secrets, the shared container entrypoint does
not resolve directly from `/run/secrets`. It rejects non-regular and symbolic
link entries, copies each mounted value into `/run/rembrane-secrets`, enforces
service-user ownership and mode `0400`, and only then drops privileges. The
runtime directory is a bounded private tmpfs and is not persisted.

The shipped REST API, WhatsApp gateway, mobile-share gateway, and channel
worker also accept locator variables for their bearer or HMAC credentials.
An empty locator preserves the documented environment-variable default;
otherwise use `env:VARIABLE` or `file:path` with the local resolver.
Unsupported `external:provider:key` references fail closed unless the
embedding deployment supplies that provider's resolver.

Administrative WhatsApp and mobile-share bind/unbind commands consume the
same binding-key locator variables as their gateways. Raw account, sender, and
device identifiers remain short-lived zeroizing environment inputs, while the
stable pseudonym key can stay in a protected secret file.

`ConfiguredGraphProvider::from_environment` accepts
`REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE` for standalone and custom
knowledge-graph worker deployments, resolving it before the Graphiti HTTP
transport is constructed.

`ConfiguredMemoryProvider::from_environment` similarly accepts
`REMBRANE_MEMORY_PROVIDER_TOKEN_REFERENCE` for environment-selected portable
HTTP providers. When the locator is absent it resolves
`REMBRANE_MEMORY_PROVIDER_TOKEN`; otherwise local `env:VARIABLE` and protected
`file:path` locators are supported. Resolution failures remain opaque and the
credential stays zeroizing across configuration and transport ownership.
