use std::fmt;

use crate::{PrincipalId, ReadScope, WorkspaceId};

#[derive(Clone, Eq, PartialEq)]
pub struct MemberScopeGrant {
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    scope: ReadScope,
}

impl fmt::Debug for MemberScopeGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemberScopeGrant")
            .field("workspace_id", &"<redacted>")
            .field("principal_id", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::MemberScopeGrant;
    use crate::{EntityId, PrincipalId, ReadScope, WorkspaceId};

    #[test]
    fn debug_output_redacts_member_scope_identities() {
        let grant = MemberScopeGrant::new(
            WorkspaceId::new("private_workspace"),
            PrincipalId::new("private_principal"),
            ReadScope::Entity {
                id: EntityId::new("private_entity"),
            },
        );

        let diagnostic = format!("{grant:?}");

        for private_value in ["private_workspace", "private_principal", "private_entity"] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("kind: \"entity\""));
    }
}
