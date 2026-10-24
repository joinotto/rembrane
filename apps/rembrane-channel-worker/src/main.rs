use std::time::Duration;

use anyhow::{Context, Result};
use rembrane_application::ChannelInboxWorker;
use rembrane_channel_processor_http::HttpChannelMessageProcessor;
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::WorkspaceId;
use rembrane_store_sqlite::SqliteStore;
use zeroize::Zeroizing;

const DEFAULT_BATCH_SIZE: usize = 10;
const DEFAULT_POLL_MILLISECONDS: u64 = 1_000;

struct Configuration {
    database: String,
    workspace_id: WorkspaceId,
    processor_url: String,
    processor_token: Zeroizing<String>,
    batch_size: usize,
    poll_milliseconds: u64,
    run_once: bool,
}

impl Configuration {
    fn from_environment() -> Result<Self> {
        Ok(Self {
            database: required_environment("REMBRANE_DATABASE")?,
            workspace_id: WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?),
            processor_url: required_environment("REMBRANE_CHANNEL_PROCESSOR_URL")?,
            processor_token: Zeroizing::new(required_environment(
                "REMBRANE_CHANNEL_PROCESSOR_TOKEN",
            )?),
            batch_size: positive_environment_usize(
                "REMBRANE_CHANNEL_WORKER_BATCH_SIZE",
                DEFAULT_BATCH_SIZE,
            )?,
            poll_milliseconds: positive_environment_u64(
                "REMBRANE_CHANNEL_WORKER_POLL_MILLISECONDS",
                DEFAULT_POLL_MILLISECONDS,
            )?,
            run_once: boolean_environment("REMBRANE_CHANNEL_WORKER_RUN_ONCE", false)?,
        })
    }
}

fn run(configuration: &Configuration) -> Result<()> {
    let cipher = ConfiguredRecordCipher::from_environment()
        .context("failed to load channel inbox cipher")?;
    let mut store = SqliteStore::open(&configuration.database)
        .context("failed to open channel inbox database")?
        .with_cipher(cipher);
    let mut processor = HttpChannelMessageProcessor::new(
        &configuration.processor_url,
        configuration.processor_token.to_string(),
    )
    .context("failed to configure channel processor")?;
    loop {
        let report = ChannelInboxWorker::new(&mut store, &mut processor)
            .process_batch(&configuration.workspace_id, configuration.batch_size)
            .context("failed to process channel inbox")?;
        println!(
            "channel inbox batch: attempted={}, completed={}, failed={}",
            report.attempted, report.completed, report.failed
        );
        if configuration.run_once {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(configuration.poll_milliseconds));
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))
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
    run(&Configuration::from_environment()?)
}

#[cfg(test)]
mod tests {
    use super::boolean_environment;

    #[test]
    fn absent_boolean_uses_default() {
        assert!(!boolean_environment("REMBRANE_TEST_UNSET_BOOLEAN", false).expect("default"));
    }
}
