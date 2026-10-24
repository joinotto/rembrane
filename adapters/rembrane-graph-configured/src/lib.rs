//! Deployment-selected graph provider composition.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_config::{ProviderConnection, ProviderKind, SecretReference};
use rembrane_domain::{
    KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, WorkspaceId,
};
use rembrane_graph_graphiti::GraphitiProvider;
use rembrane_graph_graphiti_http::HttpGraphitiTransport;
use rembrane_graph_native::NativeGraphProvider;
use rembrane_provider_sdk::{
    CandidateKnowledgeEdge, GraphNeighbourQuery, KnowledgeGraphProvider, ProviderError,
    ProviderManifest,
};
use rembrane_secret_local::{LocalSecretResolver, SecretResolver, resolve_provider_credentials};

pub enum ConfiguredGraphProvider {
    Native(NativeGraphProvider),
    Graphiti(Box<GraphitiProvider<HttpGraphitiTransport>>),
}

impl ConfiguredGraphProvider {
    pub fn from_environment() -> Result<Self, ProviderError> {
        match std::env::var("REMBRANE_GRAPH_PROVIDER")
            .as_deref()
            .unwrap_or("native")
        {
            "native" => Ok(Self::Native(NativeGraphProvider::new())),
            "graphiti" => {
                if std::env::var("REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT").as_deref() != Ok("true")
                {
                    return Err(ProviderError::InvalidConfiguration(
                        "Graphiti requires REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT=true".to_owned(),
                    ));
                }
                let endpoint = required_environment("REMBRANE_GRAPHITI_BASE_URL")?;
                let token_reference = configured_token_reference()?;
                let token = LocalSecretResolver
                    .resolve(&token_reference)
                    .map_err(|_| graphiti_credential_unavailable())?;
                let transport = HttpGraphitiTransport::new_with_secret(&endpoint, token)?;
                Ok(Self::Graphiti(Box::new(GraphitiProvider::connect(
                    transport,
                    request_prefix()?,
                    true,
                )?)))
            }
            _ => Err(ProviderError::InvalidConfiguration(
                "REMBRANE_GRAPH_PROVIDER must be native or graphiti".to_owned(),
            )),
        }
    }

    /// Connects Graphiti from a validated provider profile and a
    /// deployment-selected secret resolver.
    ///
    /// # Errors
    ///
    /// Returns a provider error unless the profile selects Graphiti with one
    /// credential reference and the operator explicitly permits provider
    /// plaintext processing.
    pub fn from_connection<Resolver>(
        connection: &ProviderConnection,
        resolver: &Resolver,
        allow_provider_plaintext: bool,
    ) -> Result<Self, ProviderError>
    where
        Resolver: SecretResolver + ?Sized,
    {
        if connection.kind() != ProviderKind::Graphiti
            || connection.endpoint().is_none()
            || connection.credentials().len() != 1
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti requires one endpoint and one credential reference".to_owned(),
            ));
        }
        if !allow_provider_plaintext {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti provider plaintext processing was not explicitly allowed".to_owned(),
            ));
        }
        let mut credentials = resolve_provider_credentials(resolver, connection).map_err(|_| {
            ProviderError::InvalidConfiguration("Graphiti credential unavailable".to_owned())
        })?;
        let bearer_token = credentials.pop().ok_or_else(|| {
            ProviderError::InvalidConfiguration("Graphiti credential unavailable".to_owned())
        })?;
        let transport = HttpGraphitiTransport::new_with_secret(
            connection.endpoint().ok_or_else(|| {
                ProviderError::InvalidConfiguration("Graphiti endpoint unavailable".to_owned())
            })?,
            bearer_token,
        )?;
        Ok(Self::Graphiti(Box::new(GraphitiProvider::connect(
            transport,
            request_prefix()?,
            true,
        )?)))
    }
}

impl KnowledgeGraphProvider for ConfiguredGraphProvider {
    fn manifest(&self) -> ProviderManifest {
        match self {
            Self::Native(provider) => provider.manifest(),
            Self::Graphiti(provider) => provider.manifest(),
        }
    }

    fn upsert_node(&mut self, node: KnowledgeNode) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.upsert_node(node),
            Self::Graphiti(provider) => provider.upsert_node(node),
        }
    }

    fn upsert_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.upsert_edge(edge),
            Self::Graphiti(provider) => provider.upsert_edge(edge),
        }
    }

    fn neighbours(
        &self,
        query: &GraphNeighbourQuery,
    ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError> {
        match self {
            Self::Native(provider) => provider.neighbours(query),
            Self::Graphiti(provider) => provider.neighbours(query),
        }
    }

    fn delete_node(
        &mut self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.delete_node(workspace_id, node_id, through_version),
            Self::Graphiti(provider) => {
                provider.delete_node(workspace_id, node_id, through_version)
            }
        }
    }

    fn delete_edge(
        &mut self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.delete_edge(workspace_id, edge_id, through_version),
            Self::Graphiti(provider) => {
                provider.delete_edge(workspace_id, edge_id, through_version)
            }
        }
    }
}

fn required_environment(name: &str) -> Result<String, ProviderError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProviderError::InvalidConfiguration(format!("{name} is required for Graphiti"))
        })
}

fn configured_token_reference() -> Result<SecretReference, ProviderError> {
    match std::env::var("REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE") {
        Ok(locator) => selected_token_reference(&locator),
        Err(std::env::VarError::NotPresent) => selected_token_reference(""),
        Err(_) => Err(graphiti_credential_unavailable()),
    }
}

fn selected_token_reference(locator: &str) -> Result<SecretReference, ProviderError> {
    if locator.is_empty() {
        SecretReference::environment("REMBRANE_GRAPHITI_BEARER_TOKEN")
            .map_err(|_| graphiti_credential_unavailable())
    } else {
        locator
            .parse()
            .map_err(|_| graphiti_credential_unavailable())
    }
}

fn graphiti_credential_unavailable() -> ProviderError {
    ProviderError::InvalidConfiguration("Graphiti credential unavailable".to_owned())
}

fn request_prefix() -> Result<String, ProviderError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Unavailable)?
        .as_nanos();
    Ok(format!("graph-worker-{}-{now}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement, SecretReference};
    use rembrane_provider_sdk::KnowledgeGraphProvider;
    use rembrane_secret_local::{SecretResolutionError, SecretResolver};
    use zeroize::Zeroizing;

    use super::{ConfiguredGraphProvider, request_prefix, selected_token_reference};

    struct RejectingResolver;

    impl SecretResolver for RejectingResolver {
        fn resolve(
            &self,
            _reference: &SecretReference,
        ) -> Result<Zeroizing<String>, SecretResolutionError> {
            Err(SecretResolutionError::Unavailable)
        }
    }

    #[test]
    fn native_provider_is_a_complete_default_without_configuration() {
        let provider =
            ConfiguredGraphProvider::Native(rembrane_graph_native::NativeGraphProvider::new());
        assert_eq!(provider.manifest().id, "rembrane.graph.native");
    }

    #[test]
    fn generated_request_prefix_is_safe_and_bounded() {
        let prefix = request_prefix().expect("system time should be available");
        assert!(prefix.starts_with("graph-worker-"));
        assert!(prefix.len() <= 96);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn graphiti_token_reference_defaults_and_rejects_inline_values() {
        let default = selected_token_reference("").expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_GRAPHITI_BEARER_TOKEN")
        );
        let file =
            selected_token_reference("file:/run/secrets/graphiti-token").expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/graphiti-token"));
        assert!(selected_token_reference("inline-token").is_err());
    }

    #[test]
    fn validates_profile_and_plaintext_policy_before_secret_resolution() {
        let mem0 = ProviderConnection::remote(
            ProviderKind::Mem0,
            "https://memory.example.test",
            vec![SecretReference::environment("MEMORY_TOKEN").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(ConfiguredGraphProvider::from_connection(&mem0, &RejectingResolver, true).is_err());

        let graphiti = ProviderConnection::remote(
            ProviderKind::Graphiti,
            "https://graph.example.test",
            vec![SecretReference::external("vault", "graph/token").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(
            ConfiguredGraphProvider::from_connection(&graphiti, &RejectingResolver, false).is_err()
        );
        let error =
            match ConfiguredGraphProvider::from_connection(&graphiti, &RejectingResolver, true) {
                Ok(_) => panic!("resolver failure must remain opaque"),
                Err(error) => error,
            };
        assert_eq!(
            error.to_string(),
            "invalid provider configuration: Graphiti credential unavailable"
        );
    }
}
