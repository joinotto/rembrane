//! Deployment-selected portable memory provider composition.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_memory_provider_http::HttpMemoryProviderClient;
use rembrane_provider_sdk::{
    CheckpointActivityPayload, CheckpointActivityResult, DeleteMemoryPayload, DeleteMemoryResult,
    ExplainMemoryPayload, ExplainMemoryResult, MemoryProviderConnection, MemoryProviderPolicy,
    MemoryProviderResponse, ProposeMemoryPayload, ProposeMemoryResult, ProviderError,
    RecordDisclosurePayload, RecordDisclosureResult, RecordEventPayload, RecordEventResult,
    ResolveContextPayload, ResolveContextResult, ResolveQuestionPayload, ResolveQuestionResult,
    SyncPullPayload, SyncPullResult, SyncPushPayload, SyncPushResult,
};

pub struct ConfiguredMemoryProvider {
    client: HttpMemoryProviderClient,
    connection: MemoryProviderConnection,
}

impl ConfiguredMemoryProvider {
    /// Connects to the selected portable memory provider using
    /// deployment-owned environment variables.
    ///
    /// `REMBRANE_MEMORY_PROVIDER` currently accepts `http`. The selected
    /// provider requires `REMBRANE_MEMORY_PROVIDER_BASE_URL` and
    /// `REMBRANE_MEMORY_PROVIDER_TOKEN`. An optional safe
    /// `REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX` makes request identities
    /// recognizable without containing tenant or credential material.
    ///
    /// # Errors
    ///
    /// Returns a provider error for missing, unsupported, malformed, or
    /// policy-incompatible configuration and for discovery failures.
    pub fn from_environment(policy: &MemoryProviderPolicy) -> Result<Self, ProviderError> {
        match std::env::var("REMBRANE_MEMORY_PROVIDER")
            .as_deref()
            .unwrap_or("http")
        {
            "http" => {
                let endpoint = required_environment("REMBRANE_MEMORY_PROVIDER_BASE_URL")?;
                let token = required_environment("REMBRANE_MEMORY_PROVIDER_TOKEN")?;
                let prefix = match std::env::var("REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX") {
                    Ok(value) => validate_request_prefix(value)?,
                    Err(_) => default_request_prefix()?,
                };
                let client = HttpMemoryProviderClient::new(&endpoint, token)?;
                let connection = client.connect(policy, prefix)?;
                Ok(Self { client, connection })
            }
            _ => Err(ProviderError::InvalidConfiguration(
                "REMBRANE_MEMORY_PROVIDER must be http".to_owned(),
            )),
        }
    }

    #[must_use]
    pub const fn client(&self) -> &HttpMemoryProviderClient {
        &self.client
    }

    #[must_use]
    pub const fn connection(&self) -> &MemoryProviderConnection {
        &self.connection
    }

    pub fn resolve_context(
        &self,
        payload: ResolveContextPayload,
    ) -> Result<MemoryProviderResponse<ResolveContextResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.resolve_context(&request)
    }

    pub fn resolve_question(
        &self,
        payload: ResolveQuestionPayload,
    ) -> Result<MemoryProviderResponse<ResolveQuestionResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.resolve_question(&request)
    }

    pub fn propose_memory(
        &self,
        payload: ProposeMemoryPayload,
    ) -> Result<MemoryProviderResponse<ProposeMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.propose_memory(&request)
    }

    pub fn record_events(
        &self,
        payload: RecordEventPayload,
    ) -> Result<MemoryProviderResponse<RecordEventResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.record_events(&request)
    }

    pub fn checkpoint_activity(
        &self,
        payload: CheckpointActivityPayload,
    ) -> Result<MemoryProviderResponse<CheckpointActivityResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.checkpoint_activity(&request)
    }

    pub fn record_disclosure(
        &self,
        payload: RecordDisclosurePayload,
    ) -> Result<MemoryProviderResponse<RecordDisclosureResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.record_disclosure(&request)
    }

    pub fn delete_memory(
        &self,
        payload: DeleteMemoryPayload,
    ) -> Result<MemoryProviderResponse<DeleteMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.delete_memory(&request)
    }

    pub fn explain_memory(
        &self,
        payload: ExplainMemoryPayload,
    ) -> Result<MemoryProviderResponse<ExplainMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.explain_memory(&request)
    }

    pub fn sync_pull(
        &self,
        payload: SyncPullPayload,
    ) -> Result<MemoryProviderResponse<SyncPullResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.sync_pull(&request)
    }

    pub fn sync_push(
        &self,
        payload: SyncPushPayload,
    ) -> Result<MemoryProviderResponse<SyncPushResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.sync_push(&request)
    }
}

fn required_environment(name: &str) -> Result<String, ProviderError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderError::InvalidConfiguration(format!("{name} is required")))
}

fn validate_request_prefix(value: String) -> Result<String, ProviderError> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProviderError::InvalidConfiguration(
            "REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX must contain 1 to 80 URL-safe characters"
                .to_owned(),
        ));
    }
    Ok(value)
}

fn default_request_prefix() -> Result<String, ProviderError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Unavailable)?
        .as_nanos();
    validate_request_prefix(format!("rembrane-{}-{timestamp}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::{default_request_prefix, validate_request_prefix};

    #[test]
    fn validates_explicit_request_prefixes_without_secret_material() {
        assert_eq!(
            validate_request_prefix("coding-agent_01".to_owned()).expect("prefix"),
            "coding-agent_01"
        );
        assert!(validate_request_prefix("tenant/name".to_owned()).is_err());
        assert!(validate_request_prefix("token value".to_owned()).is_err());
        assert!(validate_request_prefix(String::new()).is_err());
    }

    #[test]
    fn generates_safe_bounded_process_request_prefixes() {
        let prefix = default_request_prefix().expect("prefix");
        assert!(prefix.starts_with("rembrane-"));
        assert!(prefix.len() <= 80);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}
