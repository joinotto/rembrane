use std::sync::atomic::{AtomicU64, Ordering};

use rembrane_domain::WorkspaceId;

use crate::{ProviderError, ProviderProtocolVersion};

pub const CURRENT_GRAPHITI_PROTOCOL: ProviderProtocolVersion = ProviderProtocolVersion::new(0, 1);
pub const GRAPHITI_DISCOVERY_PATH: &str = "/.well-known/rembrane-graphiti";
pub const MAX_GRAPHITI_NAMESPACE_BYTES: usize = 255;
pub const MAX_GRAPHITI_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_GRAPHITI_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GraphitiOperation {
    UpsertNode,
    UpsertEdge,
    Neighbours,
    DeleteNode,
    DeleteEdge,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GraphitiRequestId(String);

impl GraphitiRequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti request id must contain 16 to 128 URL-safe ASCII characters".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GraphitiIdempotencyKey(String);

impl GraphitiIdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if !(16..=255).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti idempotency key must contain 16 to 255 portable ASCII characters"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A provider namespace derived exclusively from canonical workspace identity.
///
/// The constructor is intentionally not public. Adapters can never accept a
/// caller-selected Graphiti `group_id` independently of a Rembrane workspace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GraphitiNamespace(String);

impl GraphitiNamespace {
    pub fn for_workspace(workspace_id: &WorkspaceId) -> Result<Self, ProviderError> {
        let workspace = workspace_id.as_str();
        if workspace.is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti namespace requires a workspace".to_owned(),
            ));
        }
        let mut encoded = String::with_capacity(workspace.len().saturating_mul(2) + 4);
        encoded.push_str("rb_");
        for byte in workspace.bytes() {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").map_err(|_| ProviderError::Unavailable)?;
        }
        if encoded.len() > MAX_GRAPHITI_NAMESPACE_BYTES {
            return Err(ProviderError::InvalidConfiguration(
                "workspace identity exceeds Graphiti namespace capacity".to_owned(),
            ));
        }
        Ok(Self(encoded))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub trait GraphitiPayload {
    type Result;

    const OPERATION: GraphitiOperation;

    fn validate(&self) -> Result<(), ProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiRequest<Payload> {
    request_id: GraphitiRequestId,
    protocol_version: ProviderProtocolVersion,
    operation: GraphitiOperation,
    namespace: GraphitiNamespace,
    idempotency_key: Option<GraphitiIdempotencyKey>,
    payload: Payload,
}

impl<Payload: GraphitiPayload> GraphitiRequest<Payload> {
    pub fn new(
        request_id: GraphitiRequestId,
        workspace_id: &WorkspaceId,
        idempotency_key: Option<GraphitiIdempotencyKey>,
        payload: Payload,
    ) -> Result<Self, ProviderError> {
        payload.validate()?;
        let request = Self {
            request_id,
            protocol_version: CURRENT_GRAPHITI_PROTOCOL,
            operation: Payload::OPERATION,
            namespace: GraphitiNamespace::for_workspace(workspace_id)?,
            idempotency_key,
            payload,
        };
        if matches!(
            request.operation,
            GraphitiOperation::UpsertNode
                | GraphitiOperation::UpsertEdge
                | GraphitiOperation::DeleteNode
                | GraphitiOperation::DeleteEdge
        ) && request.idempotency_key.is_none()
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti mutations require an idempotency key".to_owned(),
            ));
        }
        Ok(request)
    }

    #[must_use]
    pub const fn request_id(&self) -> &GraphitiRequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn operation(&self) -> GraphitiOperation {
        self.operation
    }

    #[must_use]
    pub const fn namespace(&self) -> &GraphitiNamespace {
        &self.namespace
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&GraphitiIdempotencyKey> {
        self.idempotency_key.as_ref()
    }

    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn validate_response<'response>(
        &self,
        response: &'response GraphitiResponse<Payload::Result>,
    ) -> Result<&'response Result<Payload::Result, GraphitiErrorCode>, ProviderError> {
        if response.request_id != self.request_id
            || response.protocol_version != self.protocol_version
        {
            return Err(ProviderError::Rejected(
                "Graphiti response correlation mismatch".to_owned(),
            ));
        }
        Ok(&response.result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphitiErrorCode {
    InvalidRequest,
    Conflict,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiResponse<ResultPayload> {
    request_id: GraphitiRequestId,
    protocol_version: ProviderProtocolVersion,
    result: Result<ResultPayload, GraphitiErrorCode>,
}

impl<ResultPayload> GraphitiResponse<ResultPayload> {
    /// Reconstructs a response received from a sidecar transport.
    ///
    /// Correlation and protocol compatibility are still verified by the
    /// originating request before the result is accepted.
    #[must_use]
    pub fn from_parts(
        request_id: GraphitiRequestId,
        protocol_version: ProviderProtocolVersion,
        result: Result<ResultPayload, GraphitiErrorCode>,
    ) -> Self {
        Self {
            request_id,
            protocol_version,
            result,
        }
    }

    #[must_use]
    pub fn success(request: &GraphitiRequest<impl GraphitiPayload>, result: ResultPayload) -> Self {
        Self {
            request_id: request.request_id.clone(),
            protocol_version: request.protocol_version,
            result: Ok(result),
        }
    }

    #[must_use]
    pub fn error(
        request: &GraphitiRequest<impl GraphitiPayload>,
        error: GraphitiErrorCode,
    ) -> Self {
        Self {
            request_id: request.request_id.clone(),
            protocol_version: request.protocol_version,
            result: Err(error),
        }
    }
}

#[derive(Debug)]
pub struct GraphitiConnection {
    request_prefix: String,
    next_request: AtomicU64,
}

impl GraphitiConnection {
    pub fn new(request_prefix: impl Into<String>) -> Result<Self, ProviderError> {
        let request_prefix = request_prefix.into();
        if !(8..=96).contains(&request_prefix.len())
            || !request_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti request prefix must contain 8 to 96 URL-safe ASCII characters".to_owned(),
            ));
        }
        Ok(Self {
            request_prefix,
            next_request: AtomicU64::new(1),
        })
    }

    pub fn request<Payload: GraphitiPayload>(
        &self,
        workspace_id: &WorkspaceId,
        idempotency_key: Option<GraphitiIdempotencyKey>,
        payload: Payload,
    ) -> Result<GraphitiRequest<Payload>, ProviderError> {
        let sequence = self.next_request.fetch_add(1, Ordering::Relaxed);
        GraphitiRequest::new(
            GraphitiRequestId::new(format!("{}_{sequence:016x}", self.request_prefix))?,
            workspace_id,
            idempotency_key,
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::WorkspaceId;

    use super::{
        GraphitiConnection, GraphitiIdempotencyKey, GraphitiOperation, GraphitiPayload,
        GraphitiResponse,
    };
    use crate::ProviderError;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Mutation;

    impl GraphitiPayload for Mutation {
        type Result = ();

        const OPERATION: GraphitiOperation = GraphitiOperation::UpsertNode;

        fn validate(&self) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[test]
    fn derives_distinct_namespaces_and_requires_mutation_idempotency() {
        let connection = GraphitiConnection::new("graphiti-test").expect("connection");
        let workspace_a = WorkspaceId::new("workspace-a");
        let workspace_b = WorkspaceId::new("workspace-b");
        assert!(connection.request(&workspace_a, None, Mutation).is_err());
        let key = || GraphitiIdempotencyKey::new("projection.node.0001").expect("key");
        let first = connection
            .request(&workspace_a, Some(key()), Mutation)
            .expect("first request");
        let second = connection
            .request(&workspace_b, Some(key()), Mutation)
            .expect("second request");
        assert_ne!(first.namespace(), second.namespace());
        assert!(!first.namespace().as_str().contains("workspace-a"));
    }

    #[test]
    fn rejects_a_response_for_another_request() {
        let connection = GraphitiConnection::new("graphiti-test").expect("connection");
        let workspace = WorkspaceId::new("workspace-a");
        let key = || GraphitiIdempotencyKey::new("projection.node.0001").expect("key");
        let first = connection
            .request(&workspace, Some(key()), Mutation)
            .expect("first request");
        let second = connection
            .request(&workspace, Some(key()), Mutation)
            .expect("second request");
        let response = GraphitiResponse::success(&second, ());
        assert!(first.validate_response(&response).is_err());
    }
}
