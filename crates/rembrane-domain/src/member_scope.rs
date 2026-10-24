use crate::{PrincipalId, ReadScope, WorkspaceId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberScopeGrant {
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    scope: ReadScope,
}

impl MemberScopeGrant {
    #[must_use]
    pub fn new(workspace_id: WorkspaceId, principal_id: PrincipalId, scope: ReadScope) -> Self {
        Self {
            workspace_id,
            principal_id,
            scope,
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
    pub const fn scope(&self) -> &ReadScope {
        &self.scope
    }
}
