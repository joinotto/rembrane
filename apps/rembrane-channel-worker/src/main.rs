use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::ChannelInboxWorker;
use rembrane_channel_processor_http::HttpChannelMessageProcessor;
use rembrane_config::SecretReference;
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::WorkspaceId;
use rembrane_secret_local::{LocalSecretResolver, SecretResolver};
use rembrane_store_sqlite::SqliteStore;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const DEFAULT_BATCH_SIZE: usize = 10;
const DEFAULT_POLL_MILLISECONDS: u64 = 1_000;
const DEFAULT_MAXIMUM_ATTEMPTS: u32 = 5;
const DEFAULT_RETRY_DELAY_SECONDS: u64 = 30;
const DEFAULT_LEASE_SECONDS: u64 = 300;
const HEX: &[u8; 16] = b"0123456789abcdef";

struct Configuration {
    database: String,
    workspace_id: WorkspaceId,
    processor_url: String,
    processor_token: Zeroizing<String>,
    batch_size: usize,
    poll_milliseconds: u64,
    maximum_attempts: u32,
    retry_delay_seconds: u64,
    lease_seconds: u64,
    lease_id: String,
    run_once: bool,
}

impl Configuration {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            database: required_environment("REMBRANE_DATABASE")?,
            workspace_id: WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?),
            processor_url: required_environment("REMBRANE_CHANNEL_PROCESSOR_URL")?,
            processor_token: resolve_processor_token()?,
            batch_size: positive_environment_usize(
                "REMBRANE_CHANNEL_WORKER_BATCH_SIZE",
                DEFAULT_BATCH_SIZE,
            )?,
            poll_milliseconds: positive_environment_u64(
                "REMBRANE_CHANNEL_WORKER_POLL_MILLISECONDS",
                DEFAULT_POLL_MILLISECONDS,
            )?,
            maximum_attempts: positive_environment_u32(
                "REMBRANE_CHANNEL_WORKER_MAXIMUM_ATTEMPTS",
                DEFAULT_MAXIMUM_ATTEMPTS,
            )?,
            retry_delay_seconds: positive_environment_u64(
                "REMBRANE_CHANNEL_WORKER_RETRY_DELAY_SECONDS",
                DEFAULT_RETRY_DELAY_SECONDS,
            )?,
            lease_seconds: positive_environment_u64(
                "REMBRANE_CHANNEL_WORKER_LEASE_SECONDS",
                DEFAULT_LEASE_SECONDS,
            )?,
            lease_id: random_lease_id()?,
            run_once: boolean_environment("REMBRANE_CHANNEL_WORKER_RUN_ONCE", false)?,
        })
    }
}

fn run(configuration: Configuration) -> Result<()> {
    let cipher = ConfiguredRecordCipher::from_environment()
        .context("failed to load channel inbox cipher")?;
    let mut store = SqliteStore::open(&configuration.database)
        .context("failed to open channel inbox database")?
        .with_cipher(cipher);
    let mut processor = HttpChannelMessageProcessor::new(
        &configuration.processor_url,
        configuration.processor_token,
    )
    .context("failed to configure channel processor")?;
    loop {
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();
        let report = ChannelInboxWorker::new(&mut store, &mut processor)
            .process_batch(
                &configuration.workspace_id,
                &configuration.lease_id,
                now_epoch_seconds,
                configuration.batch_size,
                configuration.maximum_attempts,
                configuration.retry_delay_seconds,
                configuration.lease_seconds,
            )
            .context("failed to process channel inbox")?;
        println!(
            "channel inbox batch: attempted={}, completed={}, retried={}, quarantined={}",
            report.attempted, report.completed, report.retried, report.quarantined
        );
        if configuration.run_once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(configuration.poll_milliseconds));
    }
}

fn random_lease_id() -> Result<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate channel worker lease identity"))?;
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))
}

fn resolve_processor_token() -> Result<Zeroizing<String>> {
    let reference = match std::env::var("REMBRANE_CHANNEL_PROCESSOR_TOKEN_REFERENCE") {
        Ok(locator) => selected_processor_token_reference(&locator)?,
        Err(std::env::VarError::NotPresent) => selected_processor_token_reference("")?,
        Err(error) => {
            return Err(error).context("failed to read REMBRANE_CHANNEL_PROCESSOR_TOKEN_REFERENCE");
        }
    };
    LocalSecretResolver
        .resolve(&reference)
        .map_err(|_| anyhow::anyhow!("channel processor token is unavailable or invalid"))
}

fn selected_processor_token_reference(locator: &str) -> Result<SecretReference> {
    if locator.is_empty() {
        SecretReference::environment("REMBRANE_CHANNEL_PROCESSOR_TOKEN")
            .map_err(|_| anyhow::anyhow!("invalid default channel processor token reference"))
    } else {
        locator
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid channel processor token reference"))
    }
}

fn positive_environment_usize(name: &str, default: usize) -> Result<usize> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    })
}

fn positive_environment_u64(name: &str, default: u64) -> Result<u64> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    })
}

fn positive_environment_u32(name: &str, default: u32) -> Result<u32> {
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse::<u32>()
            .ok()
            .filter(|parsed| *parsed > 0)
            .with_context(|| format!("{name} must be a positive integer"))
    })
}

fn boolean_environment(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) if value == "1" || value == "true" => Ok(true),
        Ok(value) if value == "0" || value == "false" => Ok(false),
        Ok(_) => anyhow::bail!("{name} must be 0, 1, false, or true"),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("failed to read {name}")),
    }
}

fn main() -> Result<()> {
    run(Configuration::from_environment()?)
}

#[cfg(test)]
mod tests {
    use super::{boolean_environment, random_lease_id, selected_processor_token_reference};

    #[test]
    fn absent_boolean_uses_default() {
        assert!(!boolean_environment("REMBRANE_TEST_UNSET_BOOLEAN", false).expect("default"));
    }

    #[test]
    fn lease_identity_is_random_and_storage_safe() {
        let first = random_lease_id().expect("first lease identity");
        let second = random_lease_id().expect("second lease identity");
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn processor_token_locator_defaults_and_rejects_inline_values() {
        let default =
            selected_processor_token_reference("").expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_CHANNEL_PROCESSOR_TOKEN")
        );

        let file = selected_processor_token_reference("file:/run/secrets/processor-token")
            .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/processor-token"));
        assert!(selected_processor_token_reference("raw-token").is_err());
    }
}
