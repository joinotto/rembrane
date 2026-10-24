//! Local secret resolution without embedding credential values in configuration.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;

use rembrane_config::{ProviderConnection, SecretReference, SecretReferenceSource};
use zeroize::Zeroizing;

pub const MAX_RESOLVED_SECRET_BYTES: usize = 65_536;

/// Application-owned boundary for resolving one validated secret reference.
///
/// Cloud vault, keychain, and workload-identity adapters can implement this
/// trait without exposing their credentials or resolved values to canonical
/// configuration.
pub trait SecretResolver {
    /// Resolves a reference into a short-lived zeroizing value.
    ///
    /// # Errors
    ///
    /// Returns an opaque error when the source is unsupported, unavailable,
    /// unsafe, empty, oversized, or not valid UTF-8.
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<String>, SecretResolutionError>;
}

/// Resolves a validated provider profile's ordered credential references.
///
/// Every returned value retains its own zeroization guard. The function stops
/// at the first failure and drops all values already resolved for that
/// attempt, wiping them before returning the opaque error.
///
/// # Errors
///
/// Returns the resolver's opaque error for the first unavailable, unsupported,
/// unsafe, or invalid reference.
pub fn resolve_provider_credentials<Resolver>(
    resolver: &Resolver,
    connection: &ProviderConnection,
) -> Result<Vec<Zeroizing<String>>, SecretResolutionError>
where
    Resolver: SecretResolver + ?Sized,
{
    connection
        .credentials()
        .iter()
        .map(|reference| resolver.resolve(reference))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretResolutionError {
    UnsupportedSource,
    Unavailable,
    UnsafeFile,
    InvalidValue,
}

impl Display for SecretResolutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSource => "secret source is not supported by this resolver",
            Self::Unavailable => "secret could not be resolved",
            Self::UnsafeFile => "secret file is not a protected regular file",
            Self::InvalidValue => "resolved secret is empty, oversized, or invalid",
        })
    }
}

impl Error for SecretResolutionError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct LocalSecretResolver;

impl SecretResolver for LocalSecretResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<Zeroizing<String>, SecretResolutionError> {
        match reference.source() {
            SecretReferenceSource::Environment => {
                let variable = reference
                    .environment_variable()
                    .ok_or(SecretResolutionError::InvalidValue)?;
                let value =
                    std::env::var(variable).map_err(|_| SecretResolutionError::Unavailable)?;
                validate_value(Zeroizing::new(value))
            }
            SecretReferenceSource::File => {
                let path = reference
                    .file_path()
                    .ok_or(SecretResolutionError::InvalidValue)?;
                resolve_file(path)
            }
            SecretReferenceSource::External => Err(SecretResolutionError::UnsupportedSource),
        }
    }
}

fn resolve_file(path: &str) -> Result<Zeroizing<String>, SecretResolutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| SecretResolutionError::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RESOLVED_SECRET_BYTES as u64
    {
        return Err(SecretResolutionError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SecretResolutionError::UnsafeFile);
        }
    }

    let mut bytes = Zeroizing::new(fs::read(path).map_err(|_| SecretResolutionError::Unavailable)?);
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if std::str::from_utf8(bytes.as_slice()).is_err() {
        return Err(SecretResolutionError::InvalidValue);
    }
    let value = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Zeroizing::new(value),
        Err(error) => {
            let _guard = Zeroizing::new(error.into_bytes());
            return Err(SecretResolutionError::InvalidValue);
        }
    };
    validate_value(value)
}

fn validate_value(value: Zeroizing<String>) -> Result<Zeroizing<String>, SecretResolutionError> {
    if value.is_empty() || value.len() > MAX_RESOLVED_SECRET_BYTES || value.as_bytes().contains(&0)
    {
        return Err(SecretResolutionError::InvalidValue);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rembrane_config::SecretReference;
    use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement};
    use zeroize::Zeroizing;

    use super::{
        LocalSecretResolver, MAX_RESOLVED_SECRET_BYTES, SecretResolutionError, SecretResolver,
        resolve_provider_credentials,
    };

    #[test]
    fn resolves_existing_environment_without_copying_it_into_configuration() {
        let reference = SecretReference::environment("PATH").expect("reference");
        let value = LocalSecretResolver
            .resolve(&reference)
            .expect("PATH should be available");
        assert!(!value.is_empty());
        assert!(!format!("{reference:?}").contains(value.as_str()));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_only_bounded_protected_regular_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "rembrane-secret-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("temporary directory");
        let secret_path = directory.join("secret");
        fs::write(&secret_path, b"resolved-secret\n").expect("secret file");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
            .expect("secret permissions");
        let reference =
            SecretReference::file(secret_path.to_string_lossy()).expect("file reference");
        assert_eq!(
            LocalSecretResolver
                .resolve(&reference)
                .expect("protected secret")
                .as_str(),
            "resolved-secret"
        );

        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644))
            .expect("unsafe permissions");
        assert_eq!(
            LocalSecretResolver.resolve(&reference),
            Err(SecretResolutionError::UnsafeFile)
        );
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
            .expect("restore permissions");

        let link_path = directory.join("secret-link");
        symlink(&secret_path, &link_path).expect("secret symlink");
        let link_reference =
            SecretReference::file(link_path.to_string_lossy()).expect("link reference");
        assert_eq!(
            LocalSecretResolver.resolve(&link_reference),
            Err(SecretResolutionError::UnsafeFile)
        );

        fs::write(&secret_path, vec![b'x'; MAX_RESOLVED_SECRET_BYTES + 1])
            .expect("oversized secret");
        assert_eq!(
            LocalSecretResolver.resolve(&reference),
            Err(SecretResolutionError::UnsafeFile)
        );

        fs::remove_dir_all(directory).expect("temporary cleanup");
    }

    #[test]
    fn leaves_external_secret_managers_to_pluggable_resolvers() {
        let reference =
            SecretReference::external("vault", "secret/data/rembrane").expect("reference");
        assert_eq!(
            LocalSecretResolver.resolve(&reference),
            Err(SecretResolutionError::UnsupportedSource)
        );
    }

    struct ExternalFixtureResolver;

    impl SecretResolver for ExternalFixtureResolver {
        fn resolve(
            &self,
            reference: &SecretReference,
        ) -> Result<Zeroizing<String>, SecretResolutionError> {
            let key = reference
                .external_key()
                .ok_or(SecretResolutionError::UnsupportedSource)?;
            Ok(Zeroizing::new(format!("resolved:{key}")))
        }
    }

    #[test]
    fn resolves_validated_provider_credentials_in_declared_order() {
        let connection = ProviderConnection::remote(
            ProviderKind::Graphiti,
            "https://graph.example",
            vec![
                SecretReference::external("vault", "graph/token").expect("token reference"),
                SecretReference::external("vault", "graph/model-key").expect("model reference"),
            ],
            ProviderPlacement::External,
        )
        .expect("provider connection");

        let values = resolve_provider_credentials(&ExternalFixtureResolver, &connection)
            .expect("external resolver should compose");
        assert_eq!(values[0].as_str(), "resolved:graph/token");
        assert_eq!(values[1].as_str(), "resolved:graph/model-key");
    }
}
