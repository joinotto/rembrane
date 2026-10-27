//! Experimental portable XChaCha20-Poly1305 record cipher.
//!
//! This adapter provides the record AEAD primitive only. Production use still
//! requires an audited key provider, rotation, recovery, secure device storage,
//! and independent review.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rembrane_crypto::{
    CryptoError, EncryptedPayload, EncryptionContext, MAX_ENCRYPTION_KEY_ID_BYTES, RecordCipher,
};
use rembrane_domain::WorkspaceId;
use rembrane_provider_sdk::{
    CustomerKmsAdapter, CustomerKmsGeneratedKey, CustomerKmsKeyReference, CustomerKmsKeyring,
};
use std::fmt;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
use std::process::Command;
use zeroize::Zeroizing;

const ALGORITHM: &str = "xchacha20poly1305-ietf";
const NONCE_LENGTH: usize = 24;
pub const MAX_LOCAL_KEYRING_GENERATIONS: usize = 1_024;

#[cfg(any(target_os = "windows", test))]
const WINDOWS_POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_DPAPI_UNPROTECT: &str = r"
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$blob=$null
$entropy=$null
$plain=$null
try {
    $blob=[IO.File]::ReadAllBytes($env:REMBRANE_DPAPI_BRIDGE_BLOB_PATH)
    $entropy=[Text.Encoding]::UTF8.GetBytes($env:REMBRANE_DPAPI_BRIDGE_KEY_ID)
    $plain=[Security.Cryptography.ProtectedData]::Unprotect($blob,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    -join($plain|ForEach-Object{$_.ToString('x2')})
} finally {
    if($null-ne$plain){[Array]::Clear($plain,0,$plain.Length)}
    if($null-ne$blob){[Array]::Clear($blob,0,$blob.Length)}
    if($null-ne$entropy){[Array]::Clear($entropy,0,$entropy.Length)}
}
";

#[cfg(test)]
const WINDOWS_DPAPI_PROTECT_FIXTURE: &str = r"
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$plain=$null
$entropy=$null
$blob=$null
try {
    $hex=[Console]::In.ReadToEnd()
    if($hex-notmatch'^[0-9a-fA-F]{64}$'){throw 'invalid fixture input'}
    [byte[]]$plain=for($i=0;$i-lt$hex.Length;$i+=2){[Convert]::ToByte($hex.Substring($i,2),16)}
    $entropy=[Text.Encoding]::UTF8.GetBytes($env:REMBRANE_DPAPI_BRIDGE_KEY_ID)
    $blob=[Security.Cryptography.ProtectedData]::Protect($plain,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes($env:REMBRANE_DPAPI_BRIDGE_BLOB_PATH,$blob)
} finally {
    if($null-ne$plain){[Array]::Clear($plain,0,$plain.Length)}
    if($null-ne$blob){[Array]::Clear($blob,0,$blob.Length)}
    if($null-ne$entropy){[Array]::Clear($entropy,0,$entropy.Length)}
}
";

#[cfg(any(target_os = "windows", test))]
fn windows_dpapi_command(reference: &WindowsDpapiKeyReference, script: &'static str) -> Command {
    let mut command = Command::new(WINDOWS_POWERSHELL);
    // PowerShell treats values after a string -Command as source, not $args.
    // Keep all metadata in per-child environment overrides, never command text.
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .env("REMBRANE_DPAPI_BRIDGE_BLOB_PATH", reference.blob_path())
        .env("REMBRANE_DPAPI_BRIDGE_KEY_ID", reference.key_id());
    command
}

pub struct RustCryptoRecordCipher {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct MacosKeychainKeyReference {
    key_id: String,
    service: String,
    account: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct LinuxSecretServiceKeyReference {
    key_id: String,
    service: String,
    account: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct WindowsDpapiKeyReference {
    key_id: String,
    blob_path: String,
}

impl fmt::Debug for MacosKeychainKeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosKeychainKeyReference")
            .field("key_id", &"[REDACTED]")
            .field("service", &"[REDACTED]")
            .field("account", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for LinuxSecretServiceKeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxSecretServiceKeyReference")
            .field("key_id", &"[REDACTED]")
            .field("service", &"[REDACTED]")
            .field("account", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for WindowsDpapiKeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsDpapiKeyReference")
            .field("key_id", &"[REDACTED]")
            .field("blob_path", &"[REDACTED]")
            .finish()
    }
}

impl MacosKeychainKeyReference {
    pub fn new(
        key_id: impl Into<String>,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        let service = service.into();
        let account = account.into();
        if !valid_key_metadata(&key_id)
            || !valid_key_metadata(&service)
            || !valid_key_metadata(&account)
        {
            return Err(CryptoError::KeyUnavailable);
        }
        Ok(Self {
            key_id,
            service,
            account,
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl LinuxSecretServiceKeyReference {
    pub fn new(
        key_id: impl Into<String>,
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        let service = service.into();
        let account = account.into();
        if !valid_key_metadata(&key_id)
            || !valid_key_metadata(&service)
            || !valid_key_metadata(&account)
        {
            return Err(CryptoError::KeyUnavailable);
        }
        Ok(Self {
            key_id,
            service,
            account,
        })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl WindowsDpapiKeyReference {
    pub fn new(
        key_id: impl Into<String>,
        blob_path: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        let blob_path = blob_path.into();
        if !valid_key_metadata(&key_id) || !valid_windows_blob_path(&blob_path) {
            return Err(CryptoError::KeyUnavailable);
        }
        Ok(Self { key_id, blob_path })
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn blob_path(&self) -> &str {
        &self.blob_path
    }
}

impl RustCryptoRecordCipher {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty()
            || key_id.trim() != key_id
            || key_id.len() > MAX_ENCRYPTION_KEY_ID_BYTES
            || key_id.chars().any(char::is_control)
        {
            return Err(CryptoError::KeyUnavailable);
        }
        Ok(Self {
            key_id,
            key: Zeroizing::new(key),
        })
    }

    /// Consumes one newly generated customer-KMS data key and returns a record
    /// cipher plus the opaque reference that the sidecar must persist.
    pub fn from_generated_customer_kms(
        generated: CustomerKmsGeneratedKey,
    ) -> Result<(Self, CustomerKmsKeyReference), CryptoError> {
        let reference = generated.reference().clone();
        let key = generated.into_plaintext_key();
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let cipher = Self::new(reference.provider_key_id(), key)?;
        Ok((cipher, reference))
    }

    pub fn from_environment() -> Result<Self, CryptoError> {
        let key_id =
            std::env::var("REMBRANE_WORKSPACE_KEY_ID").map_err(|_| CryptoError::KeyUnavailable)?;
        let encoded_key = Zeroizing::new(
            std::env::var("REMBRANE_WORKSPACE_KEY_HEX").map_err(|_| CryptoError::KeyUnavailable)?,
        );
        Self::from_encoded_key(key_id, encoded_key)
    }

    /// Constructs a cipher from an already resolved zeroizing hex key.
    ///
    /// # Errors
    ///
    /// Returns key-unavailable when the identifier or encoded key is invalid.
    pub fn from_encoded_key(
        key_id: impl Into<String>,
        encoded_key: Zeroizing<String>,
    ) -> Result<Self, CryptoError> {
        let key = decode_key(&encoded_key)?;
        drop(encoded_key);
        Self::new(key_id, key)
    }

    /// Resolves a hex-encoded workspace key from the current user's macOS
    /// Keychain. The service and account are lookup metadata, not secrets.
    #[cfg(target_os = "macos")]
    pub fn from_macos_keychain(
        key_id: impl Into<String>,
        service: &str,
        account: &str,
    ) -> Result<Self, CryptoError> {
        if service.trim().is_empty() || account.trim().is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let status = output.status;
        let stdout = Zeroizing::new(output.stdout);
        let stderr = Zeroizing::new(output.stderr);
        if !status.success() || !stderr.is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        let encoded =
            std::str::from_utf8(stdout.as_ref()).map_err(|_| CryptoError::KeyUnavailable)?;
        let key = decode_key(encoded.trim())?;
        Self::new(key_id, key)
    }

    pub fn from_macos_keychain_reference(
        reference: &MacosKeychainKeyReference,
    ) -> Result<Self, CryptoError> {
        Self::from_macos_keychain(
            reference.key_id.clone(),
            &reference.service,
            &reference.account,
        )
    }

    /// Resolves a hex-encoded workspace key from the current desktop session's
    /// freedesktop Secret Service through the fixed `secret-tool` client.
    #[cfg(target_os = "linux")]
    pub fn from_linux_secret_service(
        key_id: impl Into<String>,
        service: &str,
        account: &str,
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        if !valid_key_metadata(&key_id)
            || !valid_key_metadata(service)
            || !valid_key_metadata(account)
        {
            return Err(CryptoError::KeyUnavailable);
        }
        let output = Command::new("/usr/bin/secret-tool")
            .args([
                "lookup",
                "rembrane-service",
                service,
                "rembrane-account",
                account,
                "rembrane-key-id",
                &key_id,
            ])
            .output()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let status = output.status;
        let stdout = Zeroizing::new(output.stdout);
        let stderr = Zeroizing::new(output.stderr);
        if !status.success() || !stderr.is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        let encoded =
            std::str::from_utf8(stdout.as_ref()).map_err(|_| CryptoError::KeyUnavailable)?;
        let key = decode_key(encoded.trim())?;
        Self::new(key_id, key)
    }

    pub fn from_linux_secret_service_reference(
        reference: &LinuxSecretServiceKeyReference,
    ) -> Result<Self, CryptoError> {
        Self::from_linux_secret_service(
            reference.key_id.clone(),
            &reference.service,
            &reference.account,
        )
    }

    /// Resolves a workspace key protected for the current Windows user with
    /// DPAPI. The key identifier is authenticated as optional entropy, binding
    /// each protected blob to its declared key generation.
    #[cfg(target_os = "windows")]
    pub fn from_windows_dpapi(reference: &WindowsDpapiKeyReference) -> Result<Self, CryptoError> {
        let output = windows_dpapi_command(reference, WINDOWS_DPAPI_UNPROTECT)
            .output()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let status = output.status;
        let stdout = Zeroizing::new(output.stdout);
        let stderr = Zeroizing::new(output.stderr);
        if !status.success() || !stderr.is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        let encoded =
            std::str::from_utf8(stdout.as_ref()).map_err(|_| CryptoError::KeyUnavailable)?;
        let key = decode_key(encoded.trim())?;
        Self::new(reference.key_id.clone(), key)
    }

    pub fn from_windows_dpapi_reference(
        reference: &WindowsDpapiKeyReference,
    ) -> Result<Self, CryptoError> {
        Self::from_windows_dpapi(reference)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_linux_secret_service(
        _key_id: impl Into<String>,
        _service: &str,
        _account: &str,
    ) -> Result<Self, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn from_macos_keychain(
        _key_id: impl Into<String>,
        _service: &str,
        _account: &str,
    ) -> Result<Self, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn from_windows_dpapi(_reference: &WindowsDpapiKeyReference) -> Result<Self, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }

    /// Selects the configured local key source without accepting key material
    /// through command-line arguments.
    ///
    /// `environment` is the pre-alpha development mode. OS keyring providers
    /// resolve values from the current user's protected desktop session.
    pub fn from_configured_provider() -> Result<Self, CryptoError> {
        match std::env::var("REMBRANE_KEY_PROVIDER")
            .unwrap_or_else(|_| "environment".to_owned())
            .as_str()
        {
            "environment" => Self::from_environment(),
            "macos-keychain" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let service = std::env::var("REMBRANE_KEYCHAIN_SERVICE")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let account = std::env::var("REMBRANE_KEYCHAIN_ACCOUNT")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                Self::from_macos_keychain(key_id, &service, &account)
            }
            "linux-secret-service" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let service = std::env::var("REMBRANE_SECRET_SERVICE_SERVICE")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let account = std::env::var("REMBRANE_SECRET_SERVICE_ACCOUNT")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                Self::from_linux_secret_service(key_id, &service, &account)
            }
            "windows-dpapi" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let blob_path = std::env::var("REMBRANE_DPAPI_BLOB_PATH")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let reference = WindowsDpapiKeyReference::new(key_id, blob_path)?;
                Self::from_windows_dpapi(&reference)
            }
            _ => Err(CryptoError::KeyUnavailable),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// In-process keyring for staged key rotation.
///
/// New records are sealed with the active key. Existing records are opened
/// only by the key whose opaque identifier is stored in their envelope.
/// Key-provider adapters can construct this keyring after resolving key
/// material from an OS keychain, HSM, or customer-controlled KMS.
pub struct RustCryptoKeyringCipher {
    active: RustCryptoRecordCipher,
    historical: Vec<RustCryptoRecordCipher>,
}

impl RustCryptoKeyringCipher {
    pub fn new(
        active: RustCryptoRecordCipher,
        historical: Vec<RustCryptoRecordCipher>,
    ) -> Result<Self, CryptoError> {
        if historical.len() >= MAX_LOCAL_KEYRING_GENERATIONS
            || historical
                .iter()
                .any(|candidate| candidate.key_id() == active.key_id())
        {
            return Err(CryptoError::KeyUnavailable);
        }
        for (index, candidate) in historical.iter().enumerate() {
            if historical[..index]
                .iter()
                .any(|earlier| earlier.key_id() == candidate.key_id())
            {
                return Err(CryptoError::KeyUnavailable);
            }
        }
        Ok(Self { active, historical })
    }

    pub fn from_macos_keychain(
        active: &MacosKeychainKeyReference,
        historical: &[MacosKeychainKeyReference],
    ) -> Result<Self, CryptoError> {
        validate_key_references(active, historical)?;
        let active = RustCryptoRecordCipher::from_macos_keychain_reference(active)?;
        let historical = historical
            .iter()
            .map(RustCryptoRecordCipher::from_macos_keychain_reference)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(active, historical)
    }

    pub fn from_linux_secret_service(
        active: &LinuxSecretServiceKeyReference,
        historical: &[LinuxSecretServiceKeyReference],
    ) -> Result<Self, CryptoError> {
        validate_linux_key_references(active, historical)?;
        let active = RustCryptoRecordCipher::from_linux_secret_service_reference(active)?;
        let historical = historical
            .iter()
            .map(RustCryptoRecordCipher::from_linux_secret_service_reference)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(active, historical)
    }

    pub fn from_windows_dpapi(
        active: &WindowsDpapiKeyReference,
        historical: &[WindowsDpapiKeyReference],
    ) -> Result<Self, CryptoError> {
        validate_windows_key_references(active, historical)?;
        let active = RustCryptoRecordCipher::from_windows_dpapi_reference(active)?;
        let historical = historical
            .iter()
            .map(RustCryptoRecordCipher::from_windows_dpapi_reference)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(active, historical)
    }

    /// Resolves active and historical keys inside a customer-controlled
    /// sidecar. Cloud credentials and wrapped-key persistence remain outside
    /// the Rembrane service process.
    pub fn from_customer_kms<Adapter: CustomerKmsAdapter>(
        workspace_id: &WorkspaceId,
        keyring: &CustomerKmsKeyring,
        adapter: &Adapter,
    ) -> Result<Self, CryptoError> {
        let mut active = None;
        let mut historical = Vec::with_capacity(keyring.references().len().saturating_sub(1));
        for reference in keyring.references() {
            let key = keyring
                .unwrap_generation(workspace_id, reference.generation(), adapter)
                .map_err(|_| CryptoError::KeyUnavailable)?;
            let key: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::KeyUnavailable)?;
            let cipher = RustCryptoRecordCipher::new(reference.provider_key_id(), key)?;
            if reference.generation() == keyring.active_generation() {
                active = Some(cipher);
            } else {
                historical.push(cipher);
            }
        }
        Self::new(active.ok_or(CryptoError::KeyUnavailable)?, historical)
    }

    pub fn from_configured_provider() -> Result<Self, CryptoError> {
        match std::env::var("REMBRANE_KEY_PROVIDER")
            .unwrap_or_else(|_| "environment".to_owned())
            .as_str()
        {
            "environment" => Self::new(RustCryptoRecordCipher::from_environment()?, Vec::new()),
            "macos-keychain" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let service = std::env::var("REMBRANE_KEYCHAIN_SERVICE")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let account = std::env::var("REMBRANE_KEYCHAIN_ACCOUNT")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let active = MacosKeychainKeyReference::new(key_id, &service, account)?;
                let historical = std::env::var("REMBRANE_KEYCHAIN_HISTORICAL_KEYS")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| parse_keychain_history(&service, &value))
                    .transpose()?
                    .unwrap_or_default();
                Self::from_macos_keychain(&active, &historical)
            }
            "linux-secret-service" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let service = std::env::var("REMBRANE_SECRET_SERVICE_SERVICE")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let account = std::env::var("REMBRANE_SECRET_SERVICE_ACCOUNT")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let active = LinuxSecretServiceKeyReference::new(key_id, &service, account)?;
                let historical = std::env::var("REMBRANE_SECRET_SERVICE_HISTORICAL_KEYS")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| parse_linux_key_history(&service, &value))
                    .transpose()?
                    .unwrap_or_default();
                Self::from_linux_secret_service(&active, &historical)
            }
            "windows-dpapi" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let blob_path = std::env::var("REMBRANE_DPAPI_BLOB_PATH")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let active = WindowsDpapiKeyReference::new(key_id, blob_path)?;
                let historical = std::env::var("REMBRANE_DPAPI_HISTORICAL_KEYS")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| parse_windows_dpapi_history(&value))
                    .transpose()?
                    .unwrap_or_default();
                Self::from_windows_dpapi(&active, &historical)
            }
            _ => Err(CryptoError::KeyUnavailable),
        }
    }

    #[must_use]
    pub fn active_key_id(&self) -> &str {
        self.active.key_id()
    }

    fn cipher_for_key(&self, key_id: &str) -> Option<&RustCryptoRecordCipher> {
        if self.active.key_id() == key_id {
            return Some(&self.active);
        }
        self.historical
            .iter()
            .find(|candidate| candidate.key_id() == key_id)
    }
}

fn parse_linux_key_history(
    service: &str,
    value: &str,
) -> Result<Vec<LinuxSecretServiceKeyReference>, CryptoError> {
    validate_history_size(value)?;
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            let (key_id, account) = entry.split_once('=').ok_or(CryptoError::KeyUnavailable)?;
            if account.contains('=') {
                return Err(CryptoError::KeyUnavailable);
            }
            LinuxSecretServiceKeyReference::new(key_id, service, account)
        })
        .collect()
}

fn parse_windows_dpapi_history(value: &str) -> Result<Vec<WindowsDpapiKeyReference>, CryptoError> {
    validate_history_size(value)?;
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            let (key_id, blob_path) = entry.split_once('=').ok_or(CryptoError::KeyUnavailable)?;
            WindowsDpapiKeyReference::new(key_id, blob_path)
        })
        .collect()
}

fn parse_keychain_history(
    service: &str,
    value: &str,
) -> Result<Vec<MacosKeychainKeyReference>, CryptoError> {
    validate_history_size(value)?;
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            let (key_id, account) = entry.split_once('=').ok_or(CryptoError::KeyUnavailable)?;
            if account.contains('=') {
                return Err(CryptoError::KeyUnavailable);
            }
            MacosKeychainKeyReference::new(key_id, service, account)
        })
        .collect()
}

fn validate_history_size(value: &str) -> Result<(), CryptoError> {
    if value.is_empty()
        || value.split(',').take(MAX_LOCAL_KEYRING_GENERATIONS).count()
            >= MAX_LOCAL_KEYRING_GENERATIONS
    {
        return Err(CryptoError::KeyUnavailable);
    }
    Ok(())
}

fn validate_key_references(
    active: &MacosKeychainKeyReference,
    historical: &[MacosKeychainKeyReference],
) -> Result<(), CryptoError> {
    if historical
        .iter()
        .any(|candidate| candidate.key_id() == active.key_id())
    {
        return Err(CryptoError::KeyUnavailable);
    }
    for (index, candidate) in historical.iter().enumerate() {
        if historical[..index]
            .iter()
            .any(|earlier| earlier.key_id() == candidate.key_id())
        {
            return Err(CryptoError::KeyUnavailable);
        }
    }
    Ok(())
}

fn validate_linux_key_references(
    active: &LinuxSecretServiceKeyReference,
    historical: &[LinuxSecretServiceKeyReference],
) -> Result<(), CryptoError> {
    if historical
        .iter()
        .any(|candidate| candidate.key_id() == active.key_id())
    {
        return Err(CryptoError::KeyUnavailable);
    }
    for (index, candidate) in historical.iter().enumerate() {
        if historical[..index]
            .iter()
            .any(|earlier| earlier.key_id() == candidate.key_id())
        {
            return Err(CryptoError::KeyUnavailable);
        }
    }
    Ok(())
}

fn validate_windows_key_references(
    active: &WindowsDpapiKeyReference,
    historical: &[WindowsDpapiKeyReference],
) -> Result<(), CryptoError> {
    if historical
        .iter()
        .any(|candidate| candidate.key_id() == active.key_id())
    {
        return Err(CryptoError::KeyUnavailable);
    }
    for (index, candidate) in historical.iter().enumerate() {
        if historical[..index]
            .iter()
            .any(|earlier| earlier.key_id() == candidate.key_id())
        {
            return Err(CryptoError::KeyUnavailable);
        }
    }
    Ok(())
}

fn valid_key_metadata(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_windows_blob_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() >= 4
        && value.len() <= 4_096
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !value.chars().any(char::is_control)
        && !value.split('\\').any(|component| component == "..")
}

fn decode_key(encoded: &str) -> Result<[u8; 32], CryptoError> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(CryptoError::KeyUnavailable);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| CryptoError::KeyUnavailable)?;
    }
    Ok(*key)
}

impl RecordCipher for RustCryptoRecordCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::EntropyUnavailable)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
        let associated_data = context.associated_data();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        EncryptedPayload::new(ciphertext, self.key_id.clone(), ALGORITHM, nonce.to_vec())
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        if payload.algorithm() != ALGORITHM {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        if payload.key_id() != self.key_id {
            return Err(CryptoError::KeyUnavailable);
        }
        let nonce: &[u8; NONCE_LENGTH] = payload
            .nonce()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
        let associated_data = context.associated_data();
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: payload.ciphertext(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

impl RecordCipher for RustCryptoKeyringCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        self.active.seal(context, plaintext)
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher_for_key(payload.key_id())
            .ok_or(CryptoError::KeyUnavailable)?
            .open(context, payload)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rembrane_crypto::{CryptoError, EncryptionContext, PayloadPurpose, RecordCipher};
    use rembrane_domain::WorkspaceId;
    use rembrane_provider_sdk::{
        CloudKmsDecryptClient, CloudKmsDecryptRequest, CloudKmsGenerateRequest,
        CloudKmsGeneratedKey, CloudKmsKeyClient, CustomerKmsAdapter, CustomerKmsContext,
        CustomerKmsKeyReference, CustomerKmsKeyring, CustomerKmsRotationAdapter,
        GoogleCloudKmsAdapter, ProviderError,
    };
    use zeroize::Zeroizing;

    use super::{
        LinuxSecretServiceKeyReference, MAX_LOCAL_KEYRING_GENERATIONS, MacosKeychainKeyReference,
        RustCryptoKeyringCipher, RustCryptoRecordCipher, WindowsDpapiKeyReference,
        parse_keychain_history, parse_linux_key_history, parse_windows_dpapi_history,
        validate_key_references, validate_linux_key_references, validate_windows_key_references,
    };

    fn context(workspace: &str) -> EncryptionContext {
        EncryptionContext::new(
            WorkspaceId::new(workspace),
            "memory_01",
            1,
            PayloadPurpose::MemoryContent,
        )
        .expect("context is valid")
    }

    #[test]
    fn round_trips_authenticated_record() {
        let cipher = RustCryptoRecordCipher::new("key_01", [7; 32]).expect("key is valid");
        let encrypted = cipher
            .seal(&context("workspace_01"), b"Call me Hippo")
            .expect("encryption succeeds");
        let plaintext = cipher
            .open(&context("workspace_01"), &encrypted)
            .expect("decryption succeeds");

        assert_eq!(plaintext, b"Call me Hippo");
    }

    #[test]
    fn rejects_cross_workspace_substitution() {
        let cipher = RustCryptoRecordCipher::new("key_01", [7; 32]).expect("key is valid");
        let encrypted = cipher
            .seal(&context("workspace_01"), b"Call me Hippo")
            .expect("encryption succeeds");
        let error = cipher
            .open(&context("workspace_02"), &encrypted)
            .expect_err("different associated data must fail");

        assert_eq!(error, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn rejects_invalid_encoded_key() {
        assert_eq!(super::decode_key("abcd"), Err(CryptoError::KeyUnavailable));
    }

    #[test]
    fn linux_secret_service_history_is_bounded_and_duplicate_safe() {
        let active = LinuxSecretServiceKeyReference::new(
            "key_v2",
            "org.rembrane.workspace",
            "workspace_01:key_v2",
        )
        .expect("reference should validate");
        let history =
            parse_linux_key_history("org.rembrane.workspace", "key_v1=workspace_01:key_v1")
                .expect("history should parse");
        assert_eq!(history[0].key_id(), "key_v1");
        validate_linux_key_references(&active, &history).expect("distinct history should validate");
        assert!(
            parse_linux_key_history("org.rembrane.workspace", "key_v1=workspace=invalid").is_err()
        );
        assert!(
            LinuxSecretServiceKeyReference::new(
                "key_v2\nunsafe",
                "org.rembrane.workspace",
                "workspace_01"
            )
            .is_err()
        );
    }

    #[test]
    fn windows_dpapi_references_require_local_absolute_blob_paths() {
        let reference =
            WindowsDpapiKeyReference::new("key_v2", r"C:\Rembrane\workspace_01-key_v2.dpapi")
                .expect("local absolute path should validate");
        assert_eq!(reference.key_id(), "key_v2");
        assert_eq!(
            reference.blob_path(),
            r"C:\Rembrane\workspace_01-key_v2.dpapi"
        );
        let debug = format!("{reference:?}");
        assert!(!debug.contains("key_v2"));
        assert!(!debug.contains(r"C:\Rembrane"));
        let history = parse_windows_dpapi_history(r"key_v1=C:\Rembrane\workspace_01-key_v1.dpapi")
            .expect("history should parse");
        assert_eq!(history[0].key_id(), "key_v1");
        validate_windows_key_references(&reference, &history)
            .expect("distinct history should validate");

        for path in [
            r"relative\key.dpapi",
            r"\\server\share\key.dpapi",
            r"C:\Rembrane\..\key.dpapi",
            "C:\\Rembrane\\key.dpapi\n",
        ] {
            assert!(
                WindowsDpapiKeyReference::new("key_v1", path).is_err(),
                "unsafe DPAPI blob path must fail"
            );
        }
    }

    #[test]
    fn windows_dpapi_bridge_keeps_metadata_out_of_command_text() {
        let reference = WindowsDpapiKeyReference::new(
            "key_' ; $(throw 'not-code')",
            r"C:\Rembrane data\O'Brien;$(throw 'not-code')\key.dpapi",
        )
        .unwrap();
        let command = super::windows_dpapi_command(&reference, super::WINDOWS_DPAPI_UNPROTECT);
        let arguments = command.get_args().collect::<Vec<_>>();
        assert_eq!(command.get_program(), super::WINDOWS_POWERSHELL);
        assert_eq!(
            arguments,
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                super::WINDOWS_DPAPI_UNPROTECT
            ],
            "no reference values may become PowerShell command text"
        );
        assert!(!super::WINDOWS_DPAPI_UNPROTECT.contains(reference.key_id()));
        assert!(!super::WINDOWS_DPAPI_UNPROTECT.contains(reference.blob_path()));
        assert!(!super::WINDOWS_DPAPI_UNPROTECT.contains("$args"));
        assert!(!super::WINDOWS_DPAPI_UNPROTECT.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        let environment = command.get_envs().collect::<Vec<_>>();
        assert_eq!(environment.len(), 2);
        for (name, expected) in [
            ("REMBRANE_DPAPI_BRIDGE_BLOB_PATH", reference.blob_path()),
            ("REMBRANE_DPAPI_BRIDGE_KEY_ID", reference.key_id()),
        ] {
            let (_, value) = environment.iter().find(|(key, _)| *key == name).unwrap();
            assert_eq!(*value, Some(std::ffi::OsStr::new(expected)));
        }
    }

    #[test]
    fn windows_dpapi_bridge_commands_do_not_share_or_inherit_reference_overrides() {
        let first = WindowsDpapiKeyReference::new("first_key", r"C:\Private\first.dpapi").unwrap();
        let second =
            WindowsDpapiKeyReference::new("second_key", r"D:\Private\second.dpapi").unwrap();
        let first_command = super::windows_dpapi_command(&first, super::WINDOWS_DPAPI_UNPROTECT);
        let second_command = super::windows_dpapi_command(&second, super::WINDOWS_DPAPI_UNPROTECT);
        for (command, reference) in [(&first_command, &first), (&second_command, &second)] {
            let environment = command
                .get_envs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                environment[std::ffi::OsStr::new("REMBRANE_DPAPI_BRIDGE_KEY_ID")],
                Some(std::ffi::OsStr::new(reference.key_id()))
            );
            assert_eq!(
                environment[std::ffi::OsStr::new("REMBRANE_DPAPI_BRIDGE_BLOB_PATH")],
                Some(std::ffi::OsStr::new(reference.blob_path()))
            );
        }
        let fixture = super::windows_dpapi_command(&first, super::WINDOWS_DPAPI_PROTECT_FIXTURE);
        assert_eq!(fixture.get_args().count(), 5);
        assert_eq!(fixture.get_envs().count(), 2);
        assert!(!super::WINDOWS_DPAPI_PROTECT_FIXTURE.contains("$args"));
        assert!(super::WINDOWS_DPAPI_PROTECT_FIXTURE.contains("[Console]::In.ReadToEnd()"));
        assert!(!super::WINDOWS_DPAPI_PROTECT_FIXTURE.contains("REMBRANE_WORKSPACE_KEY_HEX"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_dpapi_resolves_current_user_key_without_raw_key_environment() {
        use std::{io::Write, process::Stdio};

        let blob_path = std::env::temp_dir().join(format!(
            "rembrane dpapi ' fixture-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should follow the Unix epoch")
                .as_nanos()
        ));
        let blob_path = blob_path
            .to_str()
            .expect("Windows temporary path should be Unicode")
            .to_owned();
        let key_id = "key_windows_test";
        let fixture_key = "0707070707070707070707070707070707070707070707070707070707070707";
        let reference =
            WindowsDpapiKeyReference::new(key_id, &blob_path).expect("reference should validate");
        let mut child =
            super::windows_dpapi_command(&reference, super::WINDOWS_DPAPI_PROTECT_FIXTURE)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("PowerShell should start");
        {
            let mut input = child.stdin.take().expect("fixture input should be piped");
            input
                .write_all(fixture_key.as_bytes())
                .expect("fixture key should be written");
        }
        let output = child.wait_with_output().expect("PowerShell should finish");
        assert!(
            output.status.success(),
            "PowerShell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let cipher = RustCryptoRecordCipher::from_windows_dpapi(&reference)
            .expect("DPAPI should resolve the current user's key");
        let encrypted = cipher
            .seal(&context("workspace_01"), b"protected by DPAPI")
            .expect("resolved key should seal");
        assert_eq!(
            cipher
                .open(&context("workspace_01"), &encrypted)
                .expect("resolved key should open"),
            b"protected by DPAPI"
        );
        let wrong_entropy = WindowsDpapiKeyReference::new("different_key_id", &blob_path).unwrap();
        assert!(matches!(
            RustCryptoRecordCipher::from_windows_dpapi(&wrong_entropy),
            Err(CryptoError::KeyUnavailable)
        ));

        std::fs::remove_file(blob_path).expect("fixture blob should be removed");
    }

    #[test]
    fn keyring_writes_active_key_and_reads_historical_ciphertext() {
        let old = RustCryptoRecordCipher::new("key_v1", [1; 32]).expect("old key should be valid");
        let old_payload = old
            .seal(&context("workspace_01"), b"historical")
            .expect("old key should seal");
        let keyring = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            vec![old],
        )
        .expect("distinct keyring should be valid");

        assert_eq!(
            keyring
                .open(&context("workspace_01"), &old_payload)
                .expect("historical key should remain readable"),
            b"historical"
        );
        let current = keyring
            .seal(&context("workspace_01"), b"current")
            .expect("active key should seal");
        assert_eq!(current.key_id(), "key_v2");
        assert_eq!(keyring.active_key_id(), "key_v2");
    }

    struct FixtureKms {
        generations: RefCell<Vec<u64>>,
    }

    impl CustomerKmsAdapter for FixtureKms {
        fn unwrap_key(
            &self,
            context: &CustomerKmsContext,
            reference: &CustomerKmsKeyReference,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            self.generations.borrow_mut().push(context.generation());
            Ok(Zeroizing::new(reference.wrapped_key().to_vec()))
        }
    }

    #[test]
    fn customer_kms_keyring_seals_active_and_opens_historical_records() {
        let kms = FixtureKms {
            generations: RefCell::new(Vec::new()),
        };
        let references = CustomerKmsKeyring::new(
            2,
            vec![
                CustomerKmsKeyReference::new(1, "kms-key-v1", vec![1; 32]).unwrap(),
                CustomerKmsKeyReference::new(2, "kms-key-v2", vec![2; 32]).unwrap(),
            ],
        )
        .unwrap();
        let old = RustCryptoRecordCipher::new("kms-key-v1", [1; 32]).unwrap();
        let historical = old
            .seal(&context("workspace_01"), b"historical KMS record")
            .unwrap();

        let cipher = RustCryptoKeyringCipher::from_customer_kms(
            &WorkspaceId::new("workspace_01"),
            &references,
            &kms,
        )
        .unwrap();

        assert_eq!(cipher.active_key_id(), "kms-key-v2");
        assert_eq!(
            cipher.open(&context("workspace_01"), &historical).unwrap(),
            b"historical KMS record"
        );
        assert_eq!(kms.generations.into_inner(), vec![1, 2]);
    }

    #[test]
    fn customer_kms_keyring_rejects_wrong_key_lengths() {
        let kms = FixtureKms {
            generations: RefCell::new(Vec::new()),
        };
        let references = CustomerKmsKeyring::new(
            1,
            vec![CustomerKmsKeyReference::new(1, "kms-key-v1", vec![1; 31]).unwrap()],
        )
        .unwrap();

        assert!(matches!(
            RustCryptoKeyringCipher::from_customer_kms(
                &WorkspaceId::new("workspace_01"),
                &references,
                &kms,
            ),
            Err(CryptoError::KeyUnavailable)
        ));
    }

    struct RotationCloudClient;

    impl CloudKmsDecryptClient for RotationCloudClient {
        fn decrypt(
            &self,
            _request: CloudKmsDecryptRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            Err(ProviderError::Unavailable)
        }
    }

    impl CloudKmsKeyClient for RotationCloudClient {
        fn generate_data_key(
            &self,
            request: CloudKmsGenerateRequest<'_>,
        ) -> Result<CloudKmsGeneratedKey, ProviderError> {
            assert_eq!(request.plaintext_key_bytes(), 32);
            CloudKmsGeneratedKey::new("kms-key-v3", vec![3; 48], Zeroizing::new(vec![3; 32]))
        }
    }

    #[test]
    fn generated_customer_kms_key_is_consumed_into_cipher_and_opaque_reference() {
        let adapter = GoogleCloudKmsAdapter::new(RotationCloudClient);
        let generated = adapter
            .generate_key(&CustomerKmsContext::new(WorkspaceId::new("workspace_01"), 3).unwrap())
            .unwrap();

        let (cipher, reference) =
            RustCryptoRecordCipher::from_generated_customer_kms(generated).unwrap();
        let encrypted = cipher.seal(&context("workspace_01"), b"rotated").unwrap();

        assert_eq!(cipher.key_id(), "kms-key-v3");
        assert_eq!(reference.generation(), 3);
        assert_eq!(reference.wrapped_key(), &[3; 48]);
        assert_eq!(
            cipher.open(&context("workspace_01"), &encrypted).unwrap(),
            b"rotated"
        );
    }

    #[test]
    fn keyring_rejects_duplicate_and_unknown_key_ids() {
        let duplicate = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            vec![
                RustCryptoRecordCipher::new("key_v2", [3; 32])
                    .expect("historical key should be structurally valid"),
            ],
        );
        assert!(matches!(duplicate, Err(CryptoError::KeyUnavailable)));

        let foreign = RustCryptoRecordCipher::new("foreign", [4; 32])
            .expect("foreign key should be valid")
            .seal(&context("workspace_01"), b"foreign")
            .expect("foreign key should seal");
        let keyring = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            Vec::new(),
        )
        .expect("keyring should be valid");
        assert_eq!(
            keyring.open(&context("workspace_01"), &foreign),
            Err(CryptoError::KeyUnavailable)
        );

        let excessive = (0..MAX_LOCAL_KEYRING_GENERATIONS)
            .map(|generation| {
                RustCryptoRecordCipher::new(format!("key_v{generation}"), [3; 32])
                    .expect("historical key should validate")
            })
            .collect();
        assert!(matches!(
            RustCryptoKeyringCipher::new(
                RustCryptoRecordCipher::new("active", [2; 32]).expect("active key"),
                excessive,
            ),
            Err(CryptoError::KeyUnavailable)
        ));
    }

    #[test]
    fn keychain_references_are_nonempty_and_duplicate_safe() {
        assert_eq!(
            MacosKeychainKeyReference::new("", "org.rembrane", "workspace"),
            Err(CryptoError::KeyUnavailable)
        );
        let active =
            MacosKeychainKeyReference::new("key_v2", "org.rembrane.workspace", "workspace:key_v2")
                .expect("active reference should be valid");
        let old =
            MacosKeychainKeyReference::new("key_v1", "org.rembrane.workspace", "workspace:key_v1")
                .expect("historical reference should be valid");
        assert_eq!(validate_key_references(&active, &[old]), Ok(()));
        assert_eq!(
            validate_key_references(&active, &[active.clone()]),
            Err(CryptoError::KeyUnavailable)
        );
        let debug = format!("{active:?}");
        assert!(!debug.contains("key_v2"));
        assert!(!debug.contains("org.rembrane.workspace"));
        assert!(!debug.contains("workspace:key_v2"));
    }

    #[test]
    fn parses_metadata_only_keychain_history() {
        let references = parse_keychain_history(
            "org.rembrane.workspace",
            "key_v1=workspace:key_v1,key_v0=workspace:key_v0",
        )
        .expect("history should parse");

        assert_eq!(references.len(), 2);
        assert_eq!(references[0].key_id(), "key_v1");
        assert!(parse_keychain_history("org.rembrane.workspace", "invalid").is_err());
        assert!(parse_keychain_history("org.rembrane.workspace", "key=account=extra").is_err());
        let excessive = (0..MAX_LOCAL_KEYRING_GENERATIONS)
            .map(|generation| format!("key_v{generation}=account_v{generation}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_keychain_history("org.rembrane.workspace", &excessive).is_err());
    }
}
