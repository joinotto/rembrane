# Customer KMS integration

Rembrane integrates customer KMS and HSM systems through the Key Provider
Protocol. The Rembrane process calls authenticated `manifest`, `seal`, `open`,
and optional `rotate` operations; it never receives a KMS master key or cloud
credential.

## Trust boundary

Run the key-provider sidecar in the customer's account, network, and workload
identity boundary. The sidecar owns:

- AWS KMS, Azure Key Vault/Managed HSM, Google Cloud KMS, or HSM credentials;
- mapping Rembrane workspace generations to provider key versions;
- authenticated encryption and historical-key lookup;
- replay-resistant rotation state;
- provider audit logging that excludes plaintext and key material.

Rembrane owns canonical record context, authorization, encrypted envelopes,
rotation orchestration, and receipt validation. Provider responses must contain
only ciphertext, an opaque key identifier, algorithm metadata, nonce metadata,
or a correlated rotation receipt.

Provider implementations can use the `rembrane-provider-sdk`
`CustomerKmsAdapter` and `CustomerKmsKeyring` contracts to resolve active and
historical wrapped data keys. The contract supplies stable workspace and
generation associated data, rejects duplicate generations, bounds opaque KMS
ciphertext and provider key identifiers, and returns zeroizing plaintext key
buffers only inside the customer-side process.
`RustCryptoKeyringCipher::from_customer_kms` is the reference bridge from that
contract to the record cipher: it unwraps each generation in the sidecar,
requires an exact 256-bit data key, writes with the active generation, and
retains historical generations for decrypt-only reads.

The provider SDK also supplies `AwsKmsAdapter`, `AzureKeyVaultAdapter`, and
`GoogleCloudKmsAdapter`. Each wraps an application-owned
`CloudKmsDecryptClient` and labels the canonical associated data for the
provider's encryption-context or additional-authenticated-data mechanism.
Cloud SDK construction, workload identity, retries, and credentials remain in
the customer sidecar.

## Required request binding

Every seal and open operation must cryptographically bind the complete
length-delimited context:

- workspace ID;
- record ID;
- record version;
- payload purpose.

The sidecar must reject context substitution, unknown historical keys,
unsupported algorithms, stale rotations, duplicate request identifiers, and
plaintext larger than its advertised limit.

## Cloud mappings

### AWS

Use IAM workload identity and KMS encryption context. Restrict the role to the
configured key ARN and required operations. Do not place AWS access keys in
Rembrane configuration. If envelope encryption is used, plaintext data keys
exist only inside the sidecar and must be zeroized immediately after record
AEAD processing.

### Azure

Use managed identity with a Key Vault or Managed HSM key scoped to the required
cryptographic operations. Keep vault credentials and key-version resolution in
the sidecar. Bind the canonical context as authenticated data in the record
AEAD layer.

### Google Cloud

Use workload identity with a narrowly scoped Cloud KMS CryptoKey. Keep service
account credentials outside Rembrane. Bind the canonical context as additional
authenticated data and retain provider ciphertext for historical decrypts.

## Rembrane configuration

```sh
REMBRANE_KEY_PROVIDER=http
REMBRANE_KEY_PROVIDER_BASE_URL=https://keys.internal.example
REMBRANE_KEY_PROVIDER_TOKEN='resolved-by-the-process-secret-store'
REMBRANE_KEY_PROVIDER_ALGORITHM=xchacha20poly1305-ietf
REMBRANE_KEY_PROVIDER_REQUIRE_HISTORICAL_KEYS=true
```

The shipped configured cipher also accepts
`REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE=env:VARIABLE` or a protected
`file:path` locator. When the locator is present, only reference metadata is
kept in deployment configuration and the credential remains zeroizing from
resolution through HTTP transport ownership. An unsupported external
reference fails closed unless the embedding deployment supplies its resolver.

Literal loopback HTTP is supported for a same-machine sidecar. Every other
deployment requires HTTPS. Production deployments should prefer private
networking plus workload or mutually authenticated transport; a bearer token
alone is only the protocol's minimum authentication control.

Applications may instead construct `ProviderConnection` with
`ProviderKind::KeyProvider`, one endpoint, and one `SecretReference`.
`ConfiguredRecordCipher::from_connection` resolves that reference through the
deployment-selected `SecretResolver` and transfers the zeroizing credential
directly into the HTTP transport. Configuration and canonical memory never
contain the bearer value.

## Acceptance

Before use, run `scripts/test-key-provider-http.sh` against a disposable
provider namespace. Promotion requires context-substitution denial,
historical-key behavior, exact receipt correlation, response bounds, token
redaction, and a review of the cloud IAM policy.

