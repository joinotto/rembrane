use std::error::Error;
use std::fmt::{self, Display};

use crate::{KeyRotationId, PrincipalId, ProviderId, WorkspaceId};

pub const MAX_KEY_ROTATION_RECIPIENTS: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRotationStatus {
    Required,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRotationError {
    InvalidGeneration,
    InvalidKeyId,
    AlreadyCompleted,
    InvalidProviderReceipt,
}

impl Display for KeyRotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "workspace key generation must be greater than zero",
            Self::InvalidKeyId => "completed rotation requires a safe non-empty key identifier",
            Self::AlreadyCompleted => "workspace key rotation is already completed",
            Self::InvalidProviderReceipt => {
                "key-provider rotation receipt is invalid or ambiguously scoped"
            }
        })
    }
}

impl Error for KeyRotationError {}

/// Authenticated key-provider result for one workspace generation.
///
/// The receipt contains only opaque identities and an exact recipient set,
/// never raw, wrapped, or encrypted workspace key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRotationReceipt {
    provider_id: ProviderId,
    request_id: String,
    workspace_id: WorkspaceId,
    generation: u64,
    key_id: String,
    recipient_ids: Vec<PrincipalId>,
}

impl KeyRotationReceipt {
    pub fn new(
        provider_id: ProviderId,
        request_id: impl Into<String>,
        workspace_id: WorkspaceId,
        generation: u64,
        key_id: impl Into<String>,
        mut recipient_ids: Vec<PrincipalId>,
    ) -> Result<Self, KeyRotationError> {
        let request_id = request_id.into();
        let key_id = key_id.into();
        if provider_id.as_str().is_empty()
            || provider_id.as_str().len() > 255
            || request_id.is_empty()
            || request_id.len() > 255
            || !request_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || workspace_id.as_str().is_empty()
            || generation == 0
            || recipient_ids.is_empty()
            || recipient_ids.len() > MAX_KEY_ROTATION_RECIPIENTS
            || recipient_ids
                .iter()
                .any(|recipient| recipient.as_str().is_empty())
        {
            return Err(KeyRotationError::InvalidProviderReceipt);
        }
        validate_key_id(&key_id)?;
        recipient_ids.sort();
        if recipient_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(KeyRotationError::InvalidProviderReceipt);
        }
        Ok(Self {
            provider_id,
            request_id,
            workspace_id,
            generation,
            key_id,
            recipient_ids,
        })
    }

    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn recipient_ids(&self) -> &[PrincipalId] {
        &self.recipient_ids
    }
}

/// Content-free record that a shared workspace must advance its encryption
/// generation after removing a member.
///
/// Raw keys and wrapped key material never enter this aggregate. A key
/// provider performs the cryptographic rotation and records only the new
/// opaque key identifier when completion is confirmed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceKeyRotation {
    id: KeyRotationId,
    workspace_id: WorkspaceId,
    generation: u64,
    removed_principal_id: PrincipalId,
    requested_by: PrincipalId,
    status: KeyRotationStatus,
    completed_key_id: Option<String>,
    completed_by: Option<PrincipalId>,
}

impl WorkspaceKeyRotation {
    pub fn required(
        id: KeyRotationId,
        workspace_id: WorkspaceId,
        generation: u64,
        removed_principal_id: PrincipalId,
        requested_by: PrincipalId,
    ) -> Result<Self, KeyRotationError> {
        Self::restore(
            id,
            workspace_id,
            generation,
            removed_principal_id,
            requested_by,
            KeyRotationStatus::Required,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: KeyRotationId,
        workspace_id: WorkspaceId,
        generation: u64,
        removed_principal_id: PrincipalId,
        requested_by: PrincipalId,
        status: KeyRotationStatus,
        completed_key_id: Option<String>,
        completed_by: Option<PrincipalId>,
    ) -> Result<Self, KeyRotationError> {
        if generation == 0 {
            return Err(KeyRotationError::InvalidGeneration);
        }
        match status {
            KeyRotationStatus::Required if completed_key_id.is_some() || completed_by.is_some() => {
                return Err(KeyRotationError::InvalidKeyId);
            }
            KeyRotationStatus::Completed => {
                let key_id = completed_key_id
                    .as_deref()
                    .ok_or(KeyRotationError::InvalidKeyId)?;
                validate_key_id(key_id)?;
                if completed_by.is_none() {
                    return Err(KeyRotationError::InvalidKeyId);
                }
            }
            KeyRotationStatus::Required => {}
        }
        Ok(Self {
            id,
            workspace_id,
            generation,
            removed_principal_id,
            requested_by,
            status,
            completed_key_id,
            completed_by,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &KeyRotationId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn removed_principal_id(&self) -> &PrincipalId {
        &self.removed_principal_id
    }

    #[must_use]
    pub const fn requested_by(&self) -> &PrincipalId {
        &self.requested_by
    }

    #[must_use]
    pub const fn status(&self) -> KeyRotationStatus {
        self.status
    }

    #[must_use]
    pub fn completed_key_id(&self) -> Option<&str> {
        self.completed_key_id.as_deref()
    }

    #[must_use]
    pub const fn completed_by(&self) -> Option<&PrincipalId> {
        self.completed_by.as_ref()
    }

    pub fn complete(
        mut self,
        key_id: impl Into<String>,
        completed_by: PrincipalId,
    ) -> Result<Self, KeyRotationError> {
        if self.status != KeyRotationStatus::Required {
            return Err(KeyRotationError::AlreadyCompleted);
        }
        let key_id = key_id.into();
        validate_key_id(&key_id)?;
        self.status = KeyRotationStatus::Completed;
        self.completed_key_id = Some(key_id);
        self.completed_by = Some(completed_by);
        Ok(self)
    }
}

fn validate_key_id(key_id: &str) -> Result<(), KeyRotationError> {
    if key_id.is_empty()
        || key_id.len() > 200
        || key_id.trim() != key_id
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(KeyRotationError::InvalidKeyId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{KeyRotationError, KeyRotationReceipt, KeyRotationStatus, WorkspaceKeyRotation};
    use crate::{KeyRotationId, PrincipalId, ProviderId, WorkspaceId};

    fn required() -> WorkspaceKeyRotation {
        WorkspaceKeyRotation::required(
            KeyRotationId::new("rotation_01"),
            WorkspaceId::new("workspace_01"),
            2,
            PrincipalId::new("removed_01"),
            PrincipalId::new("owner_01"),
        )
        .expect("required rotation")
    }

    #[test]
    fn required_rotation_contains_no_key_material() {
        let rotation = required();

        assert_eq!(rotation.status(), KeyRotationStatus::Required);
        assert_eq!(rotation.generation(), 2);
        assert_eq!(rotation.completed_key_id(), None);
        assert_eq!(rotation.completed_by(), None);
    }

    #[test]
    fn completion_records_only_an_opaque_key_identifier() {
        let rotation = required()
            .complete("workspace-key:v2", PrincipalId::new("owner_01"))
            .expect("rotation completion");

        assert_eq!(rotation.status(), KeyRotationStatus::Completed);
        assert_eq!(rotation.completed_key_id(), Some("workspace-key:v2"));
        assert_eq!(rotation.completed_by(), Some(&PrincipalId::new("owner_01")));
        assert_eq!(
            rotation
                .clone()
                .complete("workspace-key:v3", PrincipalId::new("owner_01")),
            Err(KeyRotationError::AlreadyCompleted)
        );
    }

    #[test]
    fn rejects_invalid_generation_and_key_identifiers() {
        assert_eq!(
            WorkspaceKeyRotation::required(
                KeyRotationId::new("rotation_01"),
                WorkspaceId::new("workspace_01"),
                0,
                PrincipalId::new("removed_01"),
                PrincipalId::new("owner_01"),
            ),
            Err(KeyRotationError::InvalidGeneration)
        );
        assert_eq!(
            required().complete("secret key value", PrincipalId::new("owner_01")),
            Err(KeyRotationError::InvalidKeyId)
        );
    }

    #[test]
    fn provider_receipt_canonicalizes_exact_recipients_without_key_material() {
        let receipt = KeyRotationReceipt::new(
            ProviderId::new("customer.kms"),
            "rotate-request-01",
            WorkspaceId::new("workspace_01"),
            2,
            "workspace-key:v2",
            vec![PrincipalId::new("zoe"), PrincipalId::new("alice")],
        )
        .expect("provider receipt");

        assert_eq!(receipt.provider_id().as_str(), "customer.kms");
        assert_eq!(receipt.request_id(), "rotate-request-01");
        assert_eq!(receipt.generation(), 2);
        assert_eq!(
            receipt.recipient_ids(),
            &[PrincipalId::new("alice"), PrincipalId::new("zoe")]
        );
    }

    #[test]
    fn provider_receipt_rejects_duplicate_or_empty_recipient_sets() {
        let receipt = |recipients| {
            KeyRotationReceipt::new(
                ProviderId::new("customer.kms"),
                "rotate-request-01",
                WorkspaceId::new("workspace_01"),
                2,
                "workspace-key:v2",
                recipients,
            )
        };

        assert_eq!(
            receipt(Vec::new()),
            Err(KeyRotationError::InvalidProviderReceipt)
        );
        assert_eq!(
            receipt(vec![PrincipalId::new("alice"), PrincipalId::new("alice")]),
            Err(KeyRotationError::InvalidProviderReceipt)
        );
    }
}
