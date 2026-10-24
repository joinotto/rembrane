use rembrane_domain::{ClientId, ReadGrant, ReadScope, WorkspaceRole, WriteGrant, WritePermission};

use crate::{ApplicationError, MembershipRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeClientCommand {
    pub client_id: ClientId,
    pub workspace_id: rembrane_domain::WorkspaceId,
    pub principal_id: rembrane_domain::PrincipalId,
    pub requested_read_scopes: Vec<ReadScope>,
    pub requested_write_permissions: Vec<WritePermission>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientGrantBundle {
    pub read: ReadGrant,
    pub write: WriteGrant,
}

pub struct AuthorizeClientService<'repository, Repository> {
    repository: &'repository Repository,
}

impl<'repository, Repository> AuthorizeClientService<'repository, Repository>
where
    Repository: MembershipRepository,
{
    pub const fn new(repository: &'repository Repository) -> Self {
        Self { repository }
    }

    pub fn execute(
        &self,
        command: AuthorizeClientCommand,
    ) -> Result<ClientGrantBundle, ApplicationError> {
        let membership = self
            .repository
            .find_membership(&command.workspace_id, &command.principal_id)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !membership.is_active() {
            return Err(ApplicationError::AccessDenied);
        }

        let write_permissions = command
            .requested_write_permissions
            .into_iter()
            .filter(|permission| role_allows(membership.role(), *permission))
            .collect();

        Ok(ClientGrantBundle {
            read: ReadGrant {
                client_id: command.client_id.clone(),
                workspace_id: command.workspace_id.clone(),
                subject_id: command.principal_id.clone(),
                scopes: command.requested_read_scopes.clone(),
            },
            write: WriteGrant {
                client_id: command.client_id,
                workspace_id: command.workspace_id,
                subject_id: command.principal_id,
                scopes: command.requested_read_scopes,
                permissions: write_permissions,
            },
        })
    }
}

const fn role_allows(role: WorkspaceRole, permission: WritePermission) -> bool {
    match role {
        WorkspaceRole::Owner | WorkspaceRole::Admin => true,
        WorkspaceRole::Member => matches!(
            permission,
            WritePermission::ProposeMemory | WritePermission::WriteCheckpoint
        ),
        WorkspaceRole::Viewer => false,
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        Membership, PrincipalId, ReadScope, WorkspaceId, WorkspaceRole, WritePermission,
    };

    use super::{AuthorizeClientCommand, AuthorizeClientService};
    use crate::{ApplicationError, MembershipRepository};

    struct Memberships {
        membership: Membership,
    }

    impl MembershipRepository for Memberships {
        fn insert_membership(&mut self, _membership: Membership) -> Result<(), ApplicationError> {
            unreachable!("not used by authorization tests")
        }

        fn find_membership(
            &self,
            workspace_id: &WorkspaceId,
            principal_id: &PrincipalId,
        ) -> Result<Option<Membership>, ApplicationError> {
            if self.membership.workspace_id() == workspace_id
                && self.membership.principal_id() == principal_id
            {
                Ok(Some(self.membership.clone()))
            } else {
                Ok(None)
            }
        }

        fn replace_membership(&mut self, _membership: Membership) -> Result<(), ApplicationError> {
            unreachable!("not used by authorization tests")
        }
    }

    fn command() -> AuthorizeClientCommand {
        AuthorizeClientCommand {
            client_id: rembrane_domain::ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            principal_id: PrincipalId::new("principal_01"),
            requested_read_scopes: vec![ReadScope::Global],
            requested_write_permissions: vec![
                WritePermission::CreateMemory,
                WritePermission::ProposeMemory,
                WritePermission::ConfirmMemory,
                WritePermission::ReviseMemory,
                WritePermission::DeleteMemory,
                WritePermission::WriteCheckpoint,
            ],
        }
    }

    #[test]
    fn member_receives_only_member_write_permissions() {
        let repository = Memberships {
            membership: Membership::new(
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                WorkspaceRole::Member,
            ),
        };

        let grants = AuthorizeClientService::new(&repository)
            .execute(command())
            .expect("active member should authorize");

        assert_eq!(
            grants.write.permissions,
            vec![
                WritePermission::ProposeMemory,
                WritePermission::WriteCheckpoint
            ]
        );
    }

    #[test]
    fn removed_owner_is_denied() {
        let repository = Memberships {
            membership: Membership::new(
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                WorkspaceRole::Owner,
            )
            .remove(),
        };

        let error = AuthorizeClientService::new(&repository)
            .execute(command())
            .expect_err("removed member should be denied");

        assert_eq!(error, ApplicationError::AccessDenied);
    }
}
