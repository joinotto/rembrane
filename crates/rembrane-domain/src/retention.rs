use std::error::Error;
use std::fmt::{self, Display};

use crate::{LegalHoldId, PrincipalId, WorkspaceId};

pub const MAX_RETENTION_DAYS: u32 = 36_500;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPeriod {
    Days(u32),
    Forever,
}

impl RetentionPeriod {
    pub fn days(days: u32) -> Result<Self, RetentionPolicyError> {
        if !(1..=MAX_RETENTION_DAYS).contains(&days) {
            return Err(RetentionPolicyError::InvalidPeriod);
        }
        Ok(Self::Days(days))
    }

    #[must_use]
    pub const fn expires_at(self, created_at_epoch_seconds: u64) -> Option<u64> {
        match self {
            Self::Days(days) => {
                created_at_epoch_seconds.checked_add((days as u64).saturating_mul(86_400))
            }
            Self::Forever => None,
        }
    }

    #[must_use]
    pub const fn is_expired_at(self, created_at_epoch_seconds: u64, now: u64) -> bool {
        match self.expires_at(created_at_epoch_seconds) {
            Some(expires_at) => now >= expires_at,
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionResource {
    UserMemory,
    ActivityCheckpoint,
    TravelResearch,
    DisclosureReceipt,
    CanonicalEvent,
    AdministrativeAudit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionPolicyError {
    InvalidWorkspace,
    InvalidVersion,
    InvalidPeriod,
    UnsafeAuditRetention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegalHoldStatus {
    Active,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegalHoldError {
    InvalidIdentity,
    InvalidVersion,
    InvalidTime,
    AlreadyReleased,
}

impl Display for LegalHoldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "legal hold identity is invalid",
            Self::InvalidVersion => "legal hold version must be greater than zero",
            Self::InvalidTime => "legal hold time is invalid",
            Self::AlreadyReleased => "legal hold is already released",
        })
    }
}

impl Error for LegalHoldError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceLegalHold {
    id: LegalHoldId,
    workspace_id: WorkspaceId,
    placed_by: PrincipalId,
    placed_at_epoch_seconds: u64,
    status: LegalHoldStatus,
    version: u64,
    released_by: Option<PrincipalId>,
    released_at_epoch_seconds: Option<u64>,
}

impl WorkspaceLegalHold {
    pub fn active(
        id: LegalHoldId,
        workspace_id: WorkspaceId,
        placed_by: PrincipalId,
        placed_at_epoch_seconds: u64,
    ) -> Result<Self, LegalHoldError> {
        Self::restore(
            id,
            workspace_id,
            placed_by,
            placed_at_epoch_seconds,
            LegalHoldStatus::Active,
            1,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: LegalHoldId,
        workspace_id: WorkspaceId,
        placed_by: PrincipalId,
        placed_at_epoch_seconds: u64,
        status: LegalHoldStatus,
        version: u64,
        released_by: Option<PrincipalId>,
        released_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, LegalHoldError> {
        if !safe_id(id.as_str())
            || !safe_id(workspace_id.as_str())
            || !safe_id(placed_by.as_str())
            || released_by.as_ref().is_some_and(|id| !safe_id(id.as_str()))
        {
            return Err(LegalHoldError::InvalidIdentity);
        }
        if version == 0 {
            return Err(LegalHoldError::InvalidVersion);
        }
        if placed_at_epoch_seconds == 0
            || released_at_epoch_seconds.is_some_and(|released| released < placed_at_epoch_seconds)
        {
            return Err(LegalHoldError::InvalidTime);
        }
        match status {
            LegalHoldStatus::Active
                if released_by.is_some() || released_at_epoch_seconds.is_some() =>
            {
                return Err(LegalHoldError::InvalidTime);
            }
            LegalHoldStatus::Released
                if released_by.is_none() || released_at_epoch_seconds.is_none() =>
            {
                return Err(LegalHoldError::InvalidTime);
            }
            LegalHoldStatus::Active | LegalHoldStatus::Released => {}
        }
        Ok(Self {
            id,
            workspace_id,
            placed_by,
            placed_at_epoch_seconds,
            status,
            version,
            released_by,
            released_at_epoch_seconds,
        })
    }

    pub fn release(
        mut self,
        released_by: PrincipalId,
        released_at_epoch_seconds: u64,
    ) -> Result<Self, LegalHoldError> {
        if self.status == LegalHoldStatus::Released {
            return Err(LegalHoldError::AlreadyReleased);
        }
        if !safe_id(released_by.as_str())
            || released_at_epoch_seconds < self.placed_at_epoch_seconds
        {
            return Err(LegalHoldError::InvalidTime);
        }
        self.status = LegalHoldStatus::Released;
        self.version = self
            .version
            .checked_add(1)
            .ok_or(LegalHoldError::InvalidVersion)?;
        self.released_by = Some(released_by);
        self.released_at_epoch_seconds = Some(released_at_epoch_seconds);
        Ok(self)
    }

    #[must_use]
    pub const fn id(&self) -> &LegalHoldId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn placed_by(&self) -> &PrincipalId {
        &self.placed_by
    }

    #[must_use]
    pub const fn placed_at_epoch_seconds(&self) -> u64 {
        self.placed_at_epoch_seconds
    }

    #[must_use]
    pub const fn status(&self) -> LegalHoldStatus {
        self.status
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn released_by(&self) -> Option<&PrincipalId> {
        self.released_by.as_ref()
    }

    #[must_use]
    pub const fn released_at_epoch_seconds(&self) -> Option<u64> {
        self.released_at_epoch_seconds
    }
}

impl Display for RetentionPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWorkspace => "retention policy workspace is invalid",
            Self::InvalidVersion => "retention policy version must be greater than zero",
            Self::InvalidPeriod => "retention period is outside the supported range",
            Self::UnsafeAuditRetention => {
                "administrative audit retention cannot be shorter than disclosure retention"
            }
        })
    }
}

impl Error for RetentionPolicyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceRetentionPolicy {
    workspace_id: WorkspaceId,
    version: u64,
    user_memory: RetentionPeriod,
    activity_checkpoint: RetentionPeriod,
    travel_research: RetentionPeriod,
    disclosure_receipt: RetentionPeriod,
    canonical_event: RetentionPeriod,
    administrative_audit: RetentionPeriod,
}

impl WorkspaceRetentionPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        version: u64,
        user_memory: RetentionPeriod,
        activity_checkpoint: RetentionPeriod,
        travel_research: RetentionPeriod,
        disclosure_receipt: RetentionPeriod,
        canonical_event: RetentionPeriod,
        administrative_audit: RetentionPeriod,
    ) -> Result<Self, RetentionPolicyError> {
        if workspace_id.as_str().is_empty() {
            return Err(RetentionPolicyError::InvalidWorkspace);
        }
        if version == 0 {
            return Err(RetentionPolicyError::InvalidVersion);
        }
        if period_days(administrative_audit) < period_days(disclosure_receipt) {
            return Err(RetentionPolicyError::UnsafeAuditRetention);
        }
        Ok(Self {
            workspace_id,
            version,
            user_memory,
            activity_checkpoint,
            travel_research,
            disclosure_receipt,
            canonical_event,
            administrative_audit,
        })
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn period(&self, resource: RetentionResource) -> RetentionPeriod {
        match resource {
            RetentionResource::UserMemory => self.user_memory,
            RetentionResource::ActivityCheckpoint => self.activity_checkpoint,
            RetentionResource::TravelResearch => self.travel_research,
            RetentionResource::DisclosureReceipt => self.disclosure_receipt,
            RetentionResource::CanonicalEvent => self.canonical_event,
            RetentionResource::AdministrativeAudit => self.administrative_audit,
        }
    }

    #[must_use]
    pub const fn may_purge(
        &self,
        resource: RetentionResource,
        created_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
        legal_hold_active: bool,
    ) -> bool {
        !legal_hold_active
            && self
                .period(resource)
                .is_expired_at(created_at_epoch_seconds, now_epoch_seconds)
    }
}

const fn period_days(period: RetentionPeriod) -> u64 {
    match period {
        RetentionPeriod::Days(days) => days as u64,
        RetentionPeriod::Forever => u64::MAX,
    }
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::{
        LegalHoldError, LegalHoldStatus, RetentionPeriod, RetentionPolicyError, RetentionResource,
        WorkspaceLegalHold, WorkspaceRetentionPolicy,
    };
    use crate::{LegalHoldId, PrincipalId, WorkspaceId};

    fn policy() -> WorkspaceRetentionPolicy {
        WorkspaceRetentionPolicy::new(
            WorkspaceId::new("workspace_01"),
            1,
            RetentionPeriod::days(30).expect("memory period"),
            RetentionPeriod::days(7).expect("checkpoint period"),
            RetentionPeriod::days(14).expect("travel period"),
            RetentionPeriod::days(90).expect("disclosure period"),
            RetentionPeriod::days(365).expect("event period"),
            RetentionPeriod::days(365).expect("audit period"),
        )
        .expect("policy")
    }

    #[test]
    fn calculates_expiry_and_legal_hold_override_without_deleting_content() {
        let policy = policy();
        let after_thirty_days = 100 + 30 * 86_400;
        assert!(policy.may_purge(RetentionResource::UserMemory, 100, after_thirty_days, false));
        assert!(!policy.may_purge(RetentionResource::UserMemory, 100, after_thirty_days, true));
        assert!(!policy.may_purge(
            RetentionResource::AdministrativeAudit,
            100,
            after_thirty_days,
            false
        ));
    }

    #[test]
    fn rejects_zero_unbounded_and_audit_shorter_than_disclosure() {
        assert_eq!(
            RetentionPeriod::days(0),
            Err(RetentionPolicyError::InvalidPeriod)
        );
        assert_eq!(
            WorkspaceRetentionPolicy::new(
                WorkspaceId::new("workspace_01"),
                1,
                RetentionPeriod::Forever,
                RetentionPeriod::Forever,
                RetentionPeriod::Forever,
                RetentionPeriod::days(90).expect("disclosure"),
                RetentionPeriod::Forever,
                RetentionPeriod::days(30).expect("audit"),
            ),
            Err(RetentionPolicyError::UnsafeAuditRetention)
        );
    }

    #[test]
    fn legal_hold_releases_once_with_monotonic_version_and_time() {
        let hold = WorkspaceLegalHold::active(
            LegalHoldId::new("hold_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("owner_01"),
            100,
        )
        .expect("active hold");
        let released = hold
            .release(PrincipalId::new("owner_01"), 200)
            .expect("release");
        assert_eq!(released.status(), LegalHoldStatus::Released);
        assert_eq!(released.version(), 2);
        assert_eq!(
            released.clone().release(PrincipalId::new("owner_01"), 300),
            Err(LegalHoldError::AlreadyReleased)
        );
    }
}
