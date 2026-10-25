//! Durable wrapped-key metadata for a customer-controlled KMS sidecar.

use std::path::Path;
use std::sync::Mutex;
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

use rembrane_domain::WorkspaceId;
use rembrane_provider_sdk::{
    CustomerKmsKeyReference, CustomerKmsKeyReferenceStore, CustomerKmsKeyring,
    MAX_CUSTOMER_KMS_GENERATIONS, MAX_KMS_KEY_ID_BYTES, MAX_KMS_WORKSPACE_ID_BYTES,
    MAX_WRAPPED_KEY_BYTES, ProviderError,
};
use rusqlite::{Connection, MAIN_DB, OptionalExtension, params};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS customer_kms_key_references (
    workspace_id TEXT NOT NULL CHECK (
        length(workspace_id) BETWEEN 1 AND 255
    ),
    generation INTEGER NOT NULL CHECK (generation > 0),
    provider_key_id TEXT NOT NULL CHECK (
        length(provider_key_id) BETWEEN 1 AND 2048
    ),
    wrapped_key BLOB NOT NULL CHECK (
        length(wrapped_key) BETWEEN 1 AND 65536
    ),
    is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
    PRIMARY KEY (workspace_id, generation)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_customer_kms_key
ON customer_kms_key_references(workspace_id) WHERE is_active = 1;
CREATE TRIGGER IF NOT EXISTS validate_customer_kms_key_insert
BEFORE INSERT ON customer_kms_key_references
WHEN length(NEW.workspace_id) NOT BETWEEN 1 AND 255
  OR length(NEW.provider_key_id) NOT BETWEEN 1 AND 2048
  OR length(NEW.wrapped_key) NOT BETWEEN 1 AND 65536
BEGIN
    SELECT RAISE(ABORT, 'invalid customer KMS key reference');
END;
CREATE TRIGGER IF NOT EXISTS validate_customer_kms_key_update
BEFORE UPDATE ON customer_kms_key_references
WHEN length(NEW.workspace_id) NOT BETWEEN 1 AND 255
  OR length(NEW.provider_key_id) NOT BETWEEN 1 AND 2048
  OR length(NEW.wrapped_key) NOT BETWEEN 1 AND 65536
BEGIN
    SELECT RAISE(ABORT, 'invalid customer KMS key reference');
END;
";

pub struct SqliteCustomerKmsKeyReferenceStore {
    connection: Mutex<Connection>,
}

impl SqliteCustomerKmsKeyReferenceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let path = path.as_ref();
        prepare_private_database_file(path)?;
        let connection = Connection::open(path).map_err(|_| ProviderError::Unavailable)?;
        Self::initialize(connection)
    }

    pub fn in_memory() -> Result<Self, ProviderError> {
        let connection = Connection::open_in_memory().map_err(|_| ProviderError::Unavailable)?;
        Self::initialize(connection)
    }

    fn initialize(connection: Connection) -> Result<Self, ProviderError> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(|_| ProviderError::Unavailable)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Inserts the first active generation for one workspace.
    pub fn initialize_workspace(
        &self,
        workspace_id: &WorkspaceId,
        reference: &CustomerKmsKeyReference,
    ) -> Result<(), ProviderError> {
        if workspace_id.as_str().trim().is_empty() || reference.generation() != 1 {
            return Err(ProviderError::InvalidConfiguration(
                "initial customer KMS generation must be one".to_owned(),
            ));
        }
        self.connection
            .lock()
            .map_err(|_| ProviderError::Unavailable)?
            .execute(
                "INSERT INTO customer_kms_key_references
                 (workspace_id, generation, provider_key_id, wrapped_key, is_active)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                params![
                    workspace_id.as_str(),
                    reference.generation(),
                    reference.provider_key_id(),
                    reference.wrapped_key()
                ],
            )
            .map_err(|_| ProviderError::Rejected("workspace keyring already exists".to_owned()))?;
        Ok(())
    }

    pub fn load_keyring(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<CustomerKmsKeyring, ProviderError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT generation,
                    CASE WHEN length(provider_key_id) BETWEEN 1 AND ?2
                        THEN provider_key_id END,
                    CASE WHEN length(wrapped_key) BETWEEN 1 AND ?3
                        THEN wrapped_key END,
                    is_active
                 FROM customer_kms_key_references
                 WHERE workspace_id = ?1
                   AND length(workspace_id) BETWEEN 1 AND ?4
                 ORDER BY generation LIMIT ?5",
            )
            .map_err(|_| ProviderError::Unavailable)?;
        let rows = statement
            .query_map(
                params![
                    workspace_id.as_str(),
                    MAX_KMS_KEY_ID_BYTES,
                    MAX_WRAPPED_KEY_BYTES,
                    MAX_KMS_WORKSPACE_ID_BYTES,
                    MAX_CUSTOMER_KMS_GENERATIONS.saturating_add(1)
                ],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .map_err(|_| ProviderError::Unavailable)?;
        let mut active = None;
        let mut references = Vec::new();
        for row in rows {
            let (generation, provider_key_id, wrapped_key, is_active) =
                row.map_err(|_| ProviderError::Unavailable)?;
            if is_active == 1 {
                if active.replace(generation).is_some() {
                    return Err(ProviderError::Rejected(
                        "workspace keyring has multiple active generations".to_owned(),
                    ));
                }
            } else if is_active != 0 {
                return Err(ProviderError::Rejected(
                    "workspace keyring has invalid active state".to_owned(),
                ));
            }
            references.push(CustomerKmsKeyReference::new(
                generation,
                provider_key_id,
                wrapped_key,
            )?);
        }
        CustomerKmsKeyring::new(active.ok_or(ProviderError::Unavailable)?, references)
    }

    /// Writes a consistent owner-only `SQLite` snapshot and verifies its
    /// integrity and required schema before returning.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), ProviderError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(ProviderError::Rejected(
                "customer KMS backup destination already exists".to_owned(),
            ));
        }
        prepare_private_database_file(destination)?;
        let result = self
            .connection
            .lock()
            .map_err(|_| ProviderError::Unavailable)?
            .backup(MAIN_DB, destination, None)
            .map_err(|_| ProviderError::Unavailable)
            .and_then(|()| verify_backup(destination));
        if result.is_err() {
            let _ = std::fs::remove_file(destination);
        }
        result
    }

    /// Restores a verified owner-only snapshot into a new destination.
    pub fn restore_to(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<Self, ProviderError> {
        let source = source.as_ref();
        let destination = destination.as_ref();
        validate_private_database_file(source)?;
        verify_backup(source)?;
        if destination.exists() {
            return Err(ProviderError::Rejected(
                "customer KMS restore destination already exists".to_owned(),
            ));
        }
        prepare_private_database_file(destination)?;
        let result = (|| {
            let mut connection =
                Connection::open(destination).map_err(|_| ProviderError::Unavailable)?;
            connection
                .restore(MAIN_DB, source, None::<fn(rusqlite::backup::Progress)>)
                .map_err(|_| ProviderError::Unavailable)?;
            drop(connection);
            verify_backup(destination)?;
            Self::open(destination)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(destination);
        }
        result
    }
}

fn verify_backup(path: &Path) -> Result<(), ProviderError> {
    let connection = Connection::open(path).map_err(|_| ProviderError::Unavailable)?;
    let integrity = connection
        .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| ProviderError::Unavailable)?;
    if integrity != "ok" {
        return Err(ProviderError::Rejected(
            "customer KMS backup failed integrity verification".to_owned(),
        ));
    }
    let table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'customer_kms_key_references'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| ProviderError::Unavailable)?
        .is_some();
    if !table_exists {
        return Err(ProviderError::Rejected(
            "customer KMS backup is missing its keyring schema".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_private_database_file(path: &Path) -> Result<(), ProviderError> {
    if path.as_os_str().is_empty() {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database path is empty".to_owned(),
        ));
    }
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database path must not be a symbolic link".to_owned(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| ProviderError::Unavailable)?;
    let metadata = file.metadata().map_err(|_| ProviderError::Unavailable)?;
    validate_private_metadata(&metadata)?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_database_file(path: &Path) -> Result<(), ProviderError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| ProviderError::Unavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database path must not be a symbolic link".to_owned(),
        ));
    }
    validate_private_metadata(&metadata)
}

#[cfg(unix)]
fn validate_private_metadata(metadata: &std::fs::Metadata) -> Result<(), ProviderError> {
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database must be an owner-only regular file".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_private_database_file(path: &Path) -> Result<(), ProviderError> {
    if path.as_os_str().is_empty() {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database path is empty".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_database_file(path: &Path) -> Result<(), ProviderError> {
    if !path.is_file() {
        return Err(ProviderError::InvalidConfiguration(
            "customer KMS database must be a regular file".to_owned(),
        ));
    }
    Ok(())
}

impl CustomerKmsKeyReferenceStore for SqliteCustomerKmsKeyReferenceStore {
    fn persist_and_activate(
        &self,
        workspace_id: &WorkspaceId,
        expected_active_generation: u64,
        reference: &CustomerKmsKeyReference,
    ) -> Result<(), ProviderError> {
        let expected_next = expected_active_generation
            .checked_add(1)
            .ok_or(ProviderError::Unavailable)?;
        if reference.generation() != expected_next {
            return Err(ProviderError::Rejected(
                "customer KMS rotation is not the strict next generation".to_owned(),
            ));
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderError::Unavailable)?;
        let transaction = connection
            .transaction()
            .map_err(|_| ProviderError::Unavailable)?;
        let active = transaction
            .query_row(
                "SELECT generation FROM customer_kms_key_references
                 WHERE workspace_id = ?1 AND is_active = 1",
                [workspace_id.as_str()],
                |row| row.get::<_, u64>(0),
            )
            .optional()
            .map_err(|_| ProviderError::Unavailable)?;
        if active != Some(expected_active_generation) {
            return Err(ProviderError::Rejected(
                "customer KMS active generation changed".to_owned(),
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE customer_kms_key_references SET is_active = 0
                 WHERE workspace_id = ?1 AND generation = ?2 AND is_active = 1",
                params![workspace_id.as_str(), expected_active_generation],
            )
            .map_err(|_| ProviderError::Unavailable)?;
        if changed != 1 {
            return Err(ProviderError::Unavailable);
        }
        transaction
            .execute(
                "INSERT INTO customer_kms_key_references
                 (workspace_id, generation, provider_key_id, wrapped_key, is_active)
                 VALUES (?1, ?2, ?3, ?4, 1)",
                params![
                    workspace_id.as_str(),
                    reference.generation(),
                    reference.provider_key_id(),
                    reference.wrapped_key()
                ],
            )
            .map_err(|_| ProviderError::Rejected("customer KMS generation conflict".to_owned()))?;
        transaction.commit().map_err(|_| ProviderError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    #[cfg(unix)]
    use std::{fs, os::unix::fs::PermissionsExt};

    use rembrane_crypto::{EncryptionContext, PayloadPurpose, RecordCipher};
    use rembrane_crypto_rustcrypto::{RustCryptoKeyringCipher, RustCryptoRecordCipher};
    use rembrane_domain::WorkspaceId;
    use rembrane_provider_sdk::{
        CloudKmsDecryptClient, CloudKmsDecryptRequest, CloudKmsGenerateRequest,
        CloudKmsGeneratedKey, CloudKmsKeyClient, CustomerKmsKeyReference,
        CustomerKmsKeyReferenceStore, GoogleCloudKmsAdapter, MAX_KMS_KEY_ID_BYTES,
        MAX_KMS_WORKSPACE_ID_BYTES, ProviderError,
    };
    use zeroize::Zeroizing;

    use super::SqliteCustomerKmsKeyReferenceStore;

    #[test]
    fn persists_active_and_historical_generations_per_workspace() {
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1; 48]).unwrap(),
            )
            .unwrap();
        store
            .persist_and_activate(
                &workspace,
                1,
                &CustomerKmsKeyReference::new(2, "key-v2", vec![2; 48]).unwrap(),
            )
            .unwrap();

        let keyring = store.load_keyring(&workspace).unwrap();
        assert_eq!(keyring.active_generation(), 2);
        assert_eq!(keyring.references().len(), 2);
        assert_eq!(keyring.references()[0].wrapped_key(), &[1; 48]);
    }

    #[test]
    fn rejects_stale_rotation_without_changing_active_generation() {
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1; 48]).unwrap(),
            )
            .unwrap();

        assert!(
            store
                .persist_and_activate(
                    &workspace,
                    2,
                    &CustomerKmsKeyReference::new(3, "key-v3", vec![3; 48]).unwrap(),
                )
                .is_err()
        );
        assert_eq!(
            store.load_keyring(&workspace).unwrap().active_generation(),
            1
        );
    }

    #[test]
    fn isolates_workspace_keyrings() {
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();
        let first = WorkspaceId::new("workspace-a");
        let second = WorkspaceId::new("workspace-b");
        store
            .initialize_workspace(
                &first,
                &CustomerKmsKeyReference::new(1, "first-key", vec![1]).unwrap(),
            )
            .unwrap();
        store
            .initialize_workspace(
                &second,
                &CustomerKmsKeyReference::new(1, "second-key", vec![2]).unwrap(),
            )
            .unwrap();

        assert_eq!(
            store.load_keyring(&first).unwrap().references()[0].provider_key_id(),
            "first-key"
        );
        assert_eq!(
            store.load_keyring(&second).unwrap().references()[0].provider_key_id(),
            "second-key"
        );
    }

    #[test]
    fn concurrent_rotation_allows_only_one_successor() {
        let store = Arc::new(SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap());
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1]).unwrap(),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for key_id in ["key-v2-a", "key-v2-b"] {
            let store = Arc::clone(&store);
            let workspace = workspace.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let reference = CustomerKmsKeyReference::new(2, key_id, vec![2]).unwrap();
                barrier.wait();
                store.persist_and_activate(&workspace, 1, &reference)
            }));
        }
        barrier.wait();
        let mut successes = 0;
        for worker in workers {
            if worker.join().unwrap().is_ok() {
                successes += 1;
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(
            store.load_keyring(&workspace).unwrap().active_generation(),
            2
        );
    }

    #[test]
    fn store_is_send_and_sync_for_shared_sidecar_workers() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteCustomerKmsKeyReferenceStore>();
    }

    struct FixtureCloudKms;

    impl CloudKmsDecryptClient for FixtureCloudKms {
        fn decrypt(
            &self,
            request: CloudKmsDecryptRequest<'_>,
        ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
            Ok(Zeroizing::new(request.wrapped_key().to_vec()))
        }
    }

    impl CloudKmsKeyClient for FixtureCloudKms {
        fn generate_data_key(
            &self,
            request: CloudKmsGenerateRequest<'_>,
        ) -> Result<CloudKmsGeneratedKey, ProviderError> {
            assert_eq!(request.plaintext_key_bytes(), 32);
            CloudKmsGeneratedKey::new("key-v2", vec![2; 32], Zeroizing::new(vec![2; 32]))
        }
    }

    fn context(workspace: &WorkspaceId) -> EncryptionContext {
        EncryptionContext::new(
            workspace.clone(),
            "memory-1",
            1,
            PayloadPurpose::MemoryContent,
        )
        .unwrap()
    }

    #[test]
    fn rotation_persists_reloads_and_preserves_historical_decryption() {
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1; 32]).unwrap(),
            )
            .unwrap();
        let old_cipher = RustCryptoRecordCipher::new("key-v1", [1; 32]).unwrap();
        let historical = old_cipher
            .seal(&context(&workspace), b"before rotation")
            .unwrap();
        let adapter = GoogleCloudKmsAdapter::new(FixtureCloudKms);
        let initial = store.load_keyring(&workspace).unwrap();

        let generated = initial
            .generate_and_persist_next(&workspace, &adapter, &store)
            .unwrap();
        let (active_cipher, persisted_reference) =
            RustCryptoRecordCipher::from_generated_customer_kms(generated).unwrap();
        let current = active_cipher
            .seal(&context(&workspace), b"after rotation")
            .unwrap();
        assert_eq!(persisted_reference.generation(), 2);

        let reloaded = store.load_keyring(&workspace).unwrap();
        let cipher =
            RustCryptoKeyringCipher::from_customer_kms(&workspace, &reloaded, &adapter).unwrap();

        assert_eq!(
            cipher.open(&context(&workspace), &historical).unwrap(),
            b"before rotation"
        );
        assert_eq!(
            cipher.open(&context(&workspace), &current).unwrap(),
            b"after rotation"
        );
    }

    #[cfg(unix)]
    fn temporary_database_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rembrane-kms-{name}-{}-{}.sqlite",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[cfg(unix)]
    #[test]
    fn creates_owner_only_database_files() {
        let path = temporary_database_path("private");
        let _ = fs::remove_file(&path);

        let store = SqliteCustomerKmsKeyReferenceStore::open(&path).unwrap();
        drop(store);

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_permissive_or_symlinked_database_files() {
        let path = temporary_database_path("permissive");
        let link = temporary_database_path("symlink");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&link);
        fs::write(&path, []).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(SqliteCustomerKmsKeyReferenceStore::open(&path).is_err());
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(SqliteCustomerKmsKeyReferenceStore::open(&link).is_err());

        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn creates_verified_owner_only_backup_with_historical_keys() {
        let source = temporary_database_path("backup-source");
        let backup = temporary_database_path("backup-copy");
        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&backup);
        let store = SqliteCustomerKmsKeyReferenceStore::open(&source).unwrap();
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1]).unwrap(),
            )
            .unwrap();
        store
            .persist_and_activate(
                &workspace,
                1,
                &CustomerKmsKeyReference::new(2, "key-v2", vec![2]).unwrap(),
            )
            .unwrap();

        store.backup_to(&backup).unwrap();

        let restored = SqliteCustomerKmsKeyReferenceStore::open(&backup).unwrap();
        let keyring = restored.load_keyring(&workspace).unwrap();
        assert_eq!(keyring.active_generation(), 2);
        assert_eq!(keyring.references().len(), 2);
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o077,
            0
        );
        drop(restored);
        drop(store);
        fs::remove_file(backup).unwrap();
        fs::remove_file(source).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn backup_refuses_to_replace_existing_file() {
        let destination = temporary_database_path("backup-existing");
        let _ = fs::remove_file(&destination);
        fs::write(&destination, b"preserve").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();

        assert!(store.backup_to(&destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"preserve");
        fs::remove_file(destination).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn restores_verified_backup_without_overwriting_destination() {
        let source = temporary_database_path("restore-source");
        let backup = temporary_database_path("restore-backup");
        let restored_path = temporary_database_path("restore-target");
        for path in [&source, &backup, &restored_path] {
            let _ = fs::remove_file(path);
        }
        let store = SqliteCustomerKmsKeyReferenceStore::open(&source).unwrap();
        let workspace = WorkspaceId::new("workspace-a");
        store
            .initialize_workspace(
                &workspace,
                &CustomerKmsKeyReference::new(1, "key-v1", vec![1]).unwrap(),
            )
            .unwrap();
        store.backup_to(&backup).unwrap();

        let restored =
            SqliteCustomerKmsKeyReferenceStore::restore_to(&backup, &restored_path).unwrap();

        assert_eq!(
            restored
                .load_keyring(&workspace)
                .unwrap()
                .active_generation(),
            1
        );
        assert_eq!(
            fs::metadata(&restored_path).unwrap().permissions().mode() & 0o077,
            0
        );
        drop(restored);
        drop(store);
        for path in [source, backup, restored_path] {
            fs::remove_file(path).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_corrupt_source_and_preserves_existing_destination() {
        let source = temporary_database_path("restore-corrupt");
        let destination = temporary_database_path("restore-existing");
        for path in [&source, &destination] {
            let _ = fs::remove_file(path);
            fs::write(path, b"preserve").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(SqliteCustomerKmsKeyReferenceStore::restore_to(&source, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"preserve");
        fs::remove_file(source).unwrap();
        fs::remove_file(destination).unwrap();
    }

    #[test]
    fn schema_rejects_oversized_rows_before_keyring_loading() {
        let store = SqliteCustomerKmsKeyReferenceStore::in_memory().unwrap();
        let connection = store.connection.lock().unwrap();

        assert!(
            connection
                .execute(
                    "INSERT INTO customer_kms_key_references
                     (workspace_id, generation, provider_key_id, wrapped_key, is_active)
                     VALUES (?1, 1, 'key', X'01', 1)",
                    ["x".repeat(MAX_KMS_WORKSPACE_ID_BYTES + 1)],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO customer_kms_key_references
                     (workspace_id, generation, provider_key_id, wrapped_key, is_active)
                     VALUES ('workspace-a', 1, ?1, X'01', 1)",
                    ["x".repeat(MAX_KMS_KEY_ID_BYTES + 1)],
                )
                .is_err()
        );
    }
}
