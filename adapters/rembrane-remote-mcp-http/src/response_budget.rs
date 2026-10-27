use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, Weak},
    time::Instant,
};

use rembrane_contracts::VerifiedRemoteAccess;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// A configuration safety ceiling, not a measured production capacity.
pub const MAX_REMOTE_MCP_ACTIVE_RESPONSES: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpResponseBudgetError {
    InvalidLimits,
    ExpiredAuthorization,
    InvalidAuthority,
    Exhausted,
    Unavailable,
}

impl fmt::Display for RemoteMcpResponseBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "invalid remote response limits",
            Self::ExpiredAuthorization => "remote response authorization expired",
            Self::InvalidAuthority => "remote response admission authority mismatch",
            Self::Exhausted => "remote response capacity unavailable",
            Self::Unavailable => "remote response admission unavailable",
        })
    }
}

impl std::error::Error for RemoteMcpResponseBudgetError {}

struct BudgetState {
    global: Arc<Semaphore>,
    workspaces: Mutex<BTreeMap<String, Weak<Semaphore>>>,
    workspace_limit: usize,
}

/// Shared, non-waiting admission for pending and active response ownership.
///
/// One instance must be shared by every route/tenant factory in a server.
/// Reserve before SDK/provider dispatch, retain through waits, and transfer the
/// permit into a guarded body. This does not bound bytes or provider tasks that
/// continue independently of the response; those need separate budgets.
#[derive(Clone)]
pub struct RemoteMcpResponseBudget {
    state: Arc<BudgetState>,
}

impl fmt::Debug for RemoteMcpResponseBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteMcpResponseBudget(<redacted>)")
    }
}

/// Move-only admission tied to original claims and their original deadline.
///
/// Dropping returns both quotas. A pending dispatcher must retain ownership
/// until its actual work finishes, not release it merely on caller cancellation.
pub struct RemoteMcpResponsePermit {
    access: VerifiedRemoteAccess,
    _workspace: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl fmt::Debug for RemoteMcpResponsePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteMcpResponsePermit(<redacted>)")
    }
}

impl RemoteMcpResponseBudget {
    /// Both limits must be positive and within the safety ceiling; the
    /// per-workspace limit cannot exceed the shared global limit.
    pub fn new(
        global_limit: usize,
        workspace_limit: usize,
    ) -> Result<Self, RemoteMcpResponseBudgetError> {
        if global_limit == 0
            || global_limit > MAX_REMOTE_MCP_ACTIVE_RESPONSES
            || workspace_limit == 0
            || workspace_limit > global_limit
        {
            return Err(RemoteMcpResponseBudgetError::InvalidLimits);
        }
        Ok(Self {
            state: Arc::new(BudgetState {
                global: Arc::new(Semaphore::new(global_limit)),
                workspaces: Mutex::new(BTreeMap::new()),
                workspace_limit,
            }),
        })
    }

    /// Rejects immediately on saturation: no unbounded waiter queue is created.
    /// Workspace buckets use verified identity, never caller-selected metadata.
    pub fn reserve(
        &self,
        access: &VerifiedRemoteAccess,
    ) -> Result<RemoteMcpResponsePermit, RemoteMcpResponseBudgetError> {
        access
            .ensure_current()
            .map_err(|_| RemoteMcpResponseBudgetError::ExpiredAuthorization)?;
        let global = self
            .state
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| RemoteMcpResponseBudgetError::Exhausted)?;
        let workspace = {
            let mut workspaces = self
                .state
                .workspaces
                .lock()
                .map_err(|_| RemoteMcpResponseBudgetError::Unavailable)?;
            // Global admission happens first, bounding live buckets. Pruning
            // stale weak entries also bounds metadata under tenant churn.
            workspaces.retain(|_, semaphore| semaphore.strong_count() > 0);
            let key = access.workspace_id().to_string();
            if let Some(semaphore) = workspaces.get(&key).and_then(Weak::upgrade) {
                semaphore
            } else {
                let semaphore = Arc::new(Semaphore::new(self.state.workspace_limit));
                workspaces.insert(key, Arc::downgrade(&semaphore));
                semaphore
            }
        };
        let workspace = workspace
            .try_acquire_owned()
            .map_err(|_| RemoteMcpResponseBudgetError::Exhausted)?;
        access
            .ensure_current()
            .map_err(|_| RemoteMcpResponseBudgetError::ExpiredAuthorization)?;
        Ok(RemoteMcpResponsePermit {
            access: access.clone(),
            _workspace: workspace,
            _global: global,
        })
    }
}

impl RemoteMcpResponsePermit {
    pub(crate) fn ensure_current_for(
        &self,
        access: &VerifiedRemoteAccess,
    ) -> Result<(), RemoteMcpResponseBudgetError> {
        if self.access != *access {
            return Err(RemoteMcpResponseBudgetError::InvalidAuthority);
        }
        self.access
            .ensure_current()
            .and_then(|()| access.ensure_current())
            .map_err(|_| RemoteMcpResponseBudgetError::ExpiredAuthorization)
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.access.validity_deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use std::collections::BTreeSet;

    fn access(workspace: &str) -> VerifiedRemoteAccess {
        RemoteTokenClaims {
            issuer: "https://issuer.example".to_owned(),
            audience: vec!["https://resource.example/mcp".to_owned()],
            subject_id: PrincipalId::new("private-owner"),
            client_id: ClientId::new("private-client"),
            workspace_id: WorkspaceId::new(workspace),
            scopes: BTreeSet::from([RemoteAccessScope::ContextRead]),
            expires_at_epoch_seconds: 1_100,
            not_before_epoch_seconds: None,
        }
        .validate_connection(
            "https://issuer.example",
            "https://resource.example/mcp",
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn invalid_limits_fail_closed() {
        for (global, workspace) in [
            (0, 1),
            (1, 0),
            (1, 2),
            (MAX_REMOTE_MCP_ACTIVE_RESPONSES + 1, 1),
            (usize::MAX, usize::MAX),
        ] {
            assert_eq!(
                RemoteMcpResponseBudget::new(global, workspace).unwrap_err(),
                RemoteMcpResponseBudgetError::InvalidLimits
            );
        }
    }

    #[test]
    fn clones_share_global_and_workspace_capacity_without_waiting() {
        let budget = RemoteMcpResponseBudget::new(2, 1).unwrap();
        let clone = budget.clone();
        let owner = access("owner");
        let first = budget.reserve(&owner).unwrap();
        assert_eq!(
            clone.reserve(&owner).unwrap_err(),
            RemoteMcpResponseBudgetError::Exhausted
        );
        // Failed workspace admission must return its temporary global slot.
        let second = clone.reserve(&access("another")).unwrap();
        assert_eq!(
            budget.reserve(&access("third")).unwrap_err(),
            RemoteMcpResponseBudgetError::Exhausted
        );
        drop(first);
        let replacement = clone.reserve(&owner).unwrap();
        drop((second, replacement));
        assert_eq!(budget.state.global.available_permits(), 2);
    }

    #[test]
    fn concurrent_reservations_cannot_split_one_workspaces_quota() {
        let budget = RemoteMcpResponseBudget::new(4, 1).unwrap();
        let start = Arc::new(std::sync::Barrier::new(9));
        let release = Arc::new(std::sync::Barrier::new(9));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut threads = Vec::new();
        for _ in 0..8 {
            let worker_budget = budget.clone();
            let worker_start = start.clone();
            let worker_release = release.clone();
            let result_sender = sender.clone();
            threads.push(std::thread::spawn(move || {
                worker_start.wait();
                let result = worker_budget.reserve(&access("same-workspace"));
                result_sender.send(result.is_ok()).unwrap();
                worker_release.wait();
                drop(result);
            }));
        }
        start.wait();
        let admitted = (0..8)
            .filter(|_| {
                receiver
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
            })
            .count();
        // Release workers before assertions so a failed fixture cannot strand
        // threads indefinitely at its own barrier.
        let unrelated = budget.reserve(&access("another-workspace"));
        release.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(admitted, 1);
        assert!(unrelated.is_ok());
        drop(unrelated);
        assert_eq!(budget.state.global.available_permits(), 4);
    }

    #[test]
    fn proof_substitution_and_expired_original_reservations_deny() {
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let proof = access("owner");
        let mut permit = budget.reserve(&proof).unwrap();
        assert_eq!(
            permit.ensure_current_for(&access("another")),
            Err(RemoteMcpResponseBudgetError::InvalidAuthority)
        );
        assert!(
            permit
                .access
                .constrain_validity(Instant::now(), 1_100)
                .is_err()
        );
        assert_eq!(
            permit.ensure_current_for(&proof),
            Err(RemoteMcpResponseBudgetError::ExpiredAuthorization)
        );
        assert_eq!(
            budget.reserve(&permit.access).unwrap_err(),
            RemoteMcpResponseBudgetError::ExpiredAuthorization
        );
        drop(permit);
        assert!(budget.reserve(&proof).is_ok());
    }

    #[test]
    fn churn_prunes_stale_bucket_metadata_and_preserves_live_quotas() {
        let budget = RemoteMcpResponseBudget::new(2, 1).unwrap();
        let owner = access("owner");
        let retained = budget.reserve(&owner).unwrap();
        for index in 0..100 {
            drop(
                budget
                    .reserve(&access(&format!("workspace-{index}")))
                    .unwrap(),
            );
            assert!(budget.state.workspaces.lock().unwrap().len() <= 2);
            assert!(budget.reserve(&owner).is_err());
        }
        drop(retained);
    }

    #[test]
    fn poisoned_metadata_lock_denies_and_returns_global_capacity() {
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let state = budget.state.clone();
        assert!(
            std::thread::spawn(move || {
                let _lock = state.workspaces.lock().unwrap();
                panic!("fixture metadata failure");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            budget.reserve(&access("owner")).unwrap_err(),
            RemoteMcpResponseBudgetError::Unavailable
        );
        assert_eq!(budget.state.global.available_permits(), 1);
    }

    #[test]
    fn diagnostic_output_does_not_expose_identity() {
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let permit = budget.reserve(&access("private-workspace")).unwrap();
        let diagnostics = format!("{budget:?} {permit:?}");
        for private in ["private-owner", "private-client", "private-workspace"] {
            assert!(!diagnostics.contains(private));
        }
    }
}
