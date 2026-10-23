use crate::{PrincipalId, WorkspaceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceKind {
    Personal,
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipStatus {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Membership {
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    role: WorkspaceRole,
    status: MembershipStatus,
}

impl Membership {
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        role: WorkspaceRole,
    ) -> Self {
        Self {
            workspace_id,
            principal_id,
            role,
            status: MembershipStatus::Active,
        }
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn role(&self) -> WorkspaceRole {
        self.role
    }

    #[must_use]
    pub const fn status(&self) -> MembershipStatus {
        self.status
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, MembershipStatus::Active)
    }

    #[must_use]
    pub const fn can_manage_members(&self) -> bool {
        self.is_active()
            && matches!(self.role, WorkspaceRole::Owner | WorkspaceRole::Admin)
    }

    #[must_use]
    pub const fn can_write_shared_memory(&self) -> bool {
        self.is_active()
            && matches!(
                self.role,
                WorkspaceRole::Owner
                    | WorkspaceRole::Admin
                    | WorkspaceRole::Member
            )
    }

    #[must_use]
    pub fn suspend(mut self) -> Self {
        self.status = MembershipStatus::Suspended;
        self
    }

    #[must_use]
    pub fn remove(mut self) -> Self {
        self.status = MembershipStatus::Removed;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Membership, WorkspaceRole};
    use crate::{PrincipalId, WorkspaceId};

    fn member(role: WorkspaceRole) -> Membership {
        Membership::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            role,
        )
    }

    #[test]
    fn member_can_write_but_cannot_manage_members() {
        let membership = member(WorkspaceRole::Member);

        assert!(membership.can_write_shared_memory());
        assert!(!membership.can_manage_members());
    }

    #[test]
    fn removed_owner_has_no_capabilities() {
        let membership = member(WorkspaceRole::Owner).remove();

        assert!(!membership.is_active());
        assert!(!membership.can_manage_members());
        assert!(!membership.can_write_shared_memory());
    }
}
