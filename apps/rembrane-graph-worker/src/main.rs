use std::time::Duration;

use anyhow::{Context, Result};
use rembrane_application::{GraphProjectionWorker, ProjectionOutcome};
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::ProviderId;
use rembrane_graph_configured::ConfiguredGraphProvider;
use rembrane_provider_sdk::KnowledgeGraphProvider;
use rembrane_store_sqlite::SqliteStore;

const DEFAULT_POLL_MILLISECONDS: u64 = 1_000;
const MAXIMUM_POLL_MILLISECONDS: u64 = 60_000;
const DEFAULT_MAXIMUM_ATTEMPTS: u32 = 5;
const MAXIMUM_ATTEMPTS: u32 = 100;

fn main() {
    if let Err(error) = run() {
        eprintln!("graph worker failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = WorkerConfig::from_environment()?;
    let cipher =
        ConfiguredRecordCipher::from_environment().context("failed to load workspace cipher")?;
    let mut repository = SqliteStore::open(&config.database)
        .context("failed to open Rembrane database")?
        .with_cipher(cipher);
    let mut provider = ConfiguredGraphProvider::from_environment()
        .context("failed to configure graph provider")?;
    let provider_id = ProviderId::new(provider.manifest().id);

    loop {
        let outcome = GraphProjectionWorker::new(
            &mut repository,
            &mut provider,
            provider_id.clone(),
            config.maximum_attempts,
        )
        .context("graph provider does not satisfy worker policy")?
        .process_next()
        .context("graph projection transition failed")?;

        match outcome {
            ProjectionOutcome::NoWork if config.run_once => return Ok(()),
            ProjectionOutcome::NoWork => std::thread::sleep(config.poll_interval),
            ProjectionOutcome::Retried => std::thread::sleep(config.poll_interval),
            ProjectionOutcome::Completed => eprintln!("graph projection completed"),
            ProjectionOutcome::Superseded => eprintln!("graph projection superseded"),
            ProjectionOutcome::Quarantined => eprintln!("graph projection quarantined"),
        }
    }
}

struct WorkerConfig {
    database: String,
    poll_interval: Duration,
    maximum_attempts: u32,
    run_once: bool,
}

impl WorkerConfig {
    fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let poll_milliseconds = parse_bounded_u64(
            std::env::var("REMBRANE_GRAPH_WORKER_POLL_MILLISECONDS").ok(),
            DEFAULT_POLL_MILLISECONDS,
            MAXIMUM_POLL_MILLISECONDS,
            "REMBRANE_GRAPH_WORKER_POLL_MILLISECONDS",
        )?;
        let maximum_attempts = parse_bounded_u32(
            std::env::var("REMBRANE_GRAPH_WORKER_MAXIMUM_ATTEMPTS").ok(),
            DEFAULT_MAXIMUM_ATTEMPTS,
            MAXIMUM_ATTEMPTS,
            "REMBRANE_GRAPH_WORKER_MAXIMUM_ATTEMPTS",
        )?;
        let run_once = match std::env::var("REMBRANE_GRAPH_WORKER_RUN_ONCE").as_deref() {
            Ok("1") => true,
            Ok("0") | Err(_) => false,
            Ok(_) => anyhow::bail!("REMBRANE_GRAPH_WORKER_RUN_ONCE must be 0 or 1"),
        };
        Ok(Self {
            database,
            poll_interval: Duration::from_millis(poll_milliseconds),
            maximum_attempts,
            run_once,
        })
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{name} is required"))
}

fn parse_bounded_u64(value: Option<String>, default: u64, maximum: u64, name: &str) -> Result<u64> {
    let parsed = value.map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .with_context(|| format!("{name} must be an integer"))
    })?;
    anyhow::ensure!(
        (1..=maximum).contains(&parsed),
        "{name} must be between 1 and {maximum}"
    );
    Ok(parsed)
}

fn parse_bounded_u32(value: Option<String>, default: u32, maximum: u32, name: &str) -> Result<u32> {
    let parsed = value.map_or(Ok(default), |value| {
        value
            .parse::<u32>()
            .with_context(|| format!("{name} must be an integer"))
    })?;
    anyhow::ensure!(
        (1..=maximum).contains(&parsed),
        "{name} must be between 1 and {maximum}"
    );
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_MAXIMUM_ATTEMPTS, DEFAULT_POLL_MILLISECONDS, parse_bounded_u32, parse_bounded_u64,
    };

    #[test]
    fn bounds_polling_and_retry_configuration() {
        assert_eq!(
            parse_bounded_u64(None, DEFAULT_POLL_MILLISECONDS, 60_000, "poll")
                .expect("default poll"),
            DEFAULT_POLL_MILLISECONDS
        );
        assert!(parse_bounded_u64(Some("0".to_owned()), 1, 60_000, "poll").is_err());
        assert!(parse_bounded_u64(Some("60001".to_owned()), 1, 60_000, "poll").is_err());
        assert_eq!(
            parse_bounded_u32(None, DEFAULT_MAXIMUM_ATTEMPTS, 100, "attempts")
                .expect("default attempts"),
            DEFAULT_MAXIMUM_ATTEMPTS
        );
        assert!(parse_bounded_u32(Some("101".to_owned()), 1, 100, "attempts").is_err());
    }
}
