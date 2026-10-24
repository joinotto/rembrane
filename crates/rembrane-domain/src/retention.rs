use std::error::Error;
use std::fmt::{self, Display};

use crate::WorkspaceId;

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

#[cfg(test)]
mod tests {
    use super::{
        RetentionPeriod, RetentionPolicyError, RetentionResource, WorkspaceRetentionPolicy,
    };
    use crate::WorkspaceId;

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
}
