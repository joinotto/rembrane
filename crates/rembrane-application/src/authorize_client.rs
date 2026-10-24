use rembrane_domain::{
    ClientId, ReadGrant, ReadPermission, ReadScope, WorkspaceRole, WriteGrant, WritePermission,
};

use crate::{ApplicationError, MemberScopeGrantRepository, MembershipRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizeClientCommand {
    pub client_id: ClientId,
    pub workspace_id: rembrane_domain::WorkspaceId,
    pub principal_id: rembrane_domain::PrincipalId,
    pub requested_read_scopes: Vec<ReadScope>,
    pub requested_read_permissions: Vec<ReadPermission>,
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
    Repository: MemberScopeGrantRepository + MembershipRepository,
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

        let read_scopes = match membership.role() {
            WorkspaceRole::Owner | WorkspaceRole::Admin => command.requested_read_scopes,
            WorkspaceRole::Member | WorkspaceRole::Viewer => {
                let allowed = self
                    .repository
                    .list_member_scope_grants(&command.workspace_id, &command.principal_id)?;
                command
                    .requested_read_scopes
                    .into_iter()
                    .filter(|requested| allowed.iter().any(|grant| grant.scope() == requested))
                    .collect()
            }
        };
        let write_permissions = command
            .requested_write_permissions
            .into_iter()
            .filter(|permission| role_allows(membership.role(), *permission))
            .collect();
        let read_permissions = command
            .requested_read_permissions
            .into_iter()
            .filter(|permission| read_role_allows(membership.role(), *permission))
            .collect();

        Ok(ClientGrantBundle {
            read: ReadGrant {
                client_id: command.client_id.clone(),
                workspace_id: command.workspace_id.clone(),
                subject_id: command.principal_id.clone(),
                scopes: read_scopes.clone(),
                permissions: read_permissions,
            },
            write: WriteGrant {
                client_id: command.client_id,
                workspace_id: command.workspace_id,
                subject_id: command.principal_id,
                scopes: read_scopes,
                permissions: write_permissions,
            },
        })
    }
}

const fn read_role_allows(role: WorkspaceRole, permission: ReadPermission) -> bool {
    match permission {
        ReadPermission::RevealTravelSourceReferences => {
            matches!(role, WorkspaceRole::Owner | WorkspaceRole::Admin)
        }
    }
}

const fn role_allows(role: WorkspaceRole, permission: WritePermission) -> bool {
    match role {
        WorkspaceRole::Owner | WorkspaceRole::Admin => true,
        WorkspaceRole::Member => matches!(
            permission,
            WritePermission::ProposeMemory
                | WritePermission::WriteCheckpoint
                | WritePermission::ReviseTrip
                | WritePermission::CaptureBookingResearch
        ),
        WorkspaceRole::Viewer => false,
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        EntityId, MemberScopeGrant, Membership, PrincipalId, ReadPermission, ReadScope,
        WorkspaceId, WorkspaceRole, WritePermission,
    };

    use super::{AuthorizeClientCommand, AuthorizeClientService};
    use crate::{ApplicationError, MemberScopeGrantRepository, MembershipRepository};

    struct Memberships {
        membership: Membership,
        scopes: Vec<MemberScopeGrant>,
    }

    impl MemberScopeGrantRepository for Memberships {
        fn insert_member_scope_grant(
            &mut self,
            _grant: MemberScopeGrant,
        ) -> Result<(), ApplicationError> {
            unreachable!("not used by authorization tests")
        }

        fn list_member_scope_grants(
            &self,
            workspace_id: &WorkspaceId,
            principal_id: &PrincipalId,
        ) -> Result<Vec<MemberScopeGrant>, ApplicationError> {
            Ok(self
                .scopes
                .iter()
                .filter(|grant| {
                    grant.workspace_id() == workspace_id && grant.principal_id() == principal_id
                })
                .cloned()
                .collect())
        }

        fn delete_member_scope_grant(
            &mut self,
            _grant: &MemberScopeGrant,
        ) -> Result<(), ApplicationError> {
            unreachable!("not used by authorization tests")
        }
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
            requested_read_permissions: vec![ReadPermission::RevealTravelSourceReferences],
            requested_write_permissions: vec![
                WritePermission::CreateMemory,
                WritePermission::ProposeMemory,
                WritePermission::ConfirmMemory,
                WritePermission::ReviseMemory,
                WritePermission::DeleteMemory,
                WritePermission::ShareMemory,
                WritePermission::WriteCheckpoint,
                WritePermission::CreateTrip,
                WritePermission::ReviseTrip,
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
            scopes: Vec::new(),
        };

        let grants = AuthorizeClientService::new(&repository)
            .execute(command())
            .expect("active member should authorize");

        assert_eq!(
            grants.write.permissions,
            vec![
                WritePermission::ProposeMemory,
                WritePermission::WriteCheckpoint,
                WritePermission::ReviseTrip,
            ]
        );
        assert_eq!(grants.read.scopes, Vec::<ReadScope>::new());
        assert_eq!(grants.read.permissions, Vec::<ReadPermission>::new());
        assert_eq!(grants.write.scopes, Vec::<ReadScope>::new());
    }

    #[test]
    fn owner_must_explicitly_request_sensitive_read_permission() {
        let repository = Memberships {
            membership: Membership::new(
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                WorkspaceRole::Owner,
            ),
            scopes: Vec::new(),
        };

        let grants = AuthorizeClientService::new(&repository)
            .execute(command())
            .expect("active owner should authorize");

        assert_eq!(
            grants.read.permissions,
            vec![ReadPermission::RevealTravelSourceReferences]
        );
        let mut without_sensitive_permission = command();
        without_sensitive_permission
            .requested_read_permissions
            .clear();
        let grants = AuthorizeClientService::new(&repository)
            .execute(without_sensitive_permission)
            .expect("active owner should authorize");
        assert_eq!(grants.read.permissions, Vec::<ReadPermission>::new());
    }

    #[test]
    fn member_receives_only_persistently_granted_entity_scope() {
        let workspace_id = WorkspaceId::new("workspace_01");
        let principal_id = PrincipalId::new("principal_01");
        let allowed = ReadScope::Entity {
            id: EntityId::new("project_allowed"),
        };
        let repository = Memberships {
            membership: Membership::new(
                workspace_id.clone(),
                principal_id.clone(),
                WorkspaceRole::Member,
            ),
            scopes: vec![MemberScopeGrant::new(
                workspace_id,
                principal_id,
                allowed.clone(),
            )],
        };
        let mut requested = command();
        requested.requested_read_scopes = vec![
            allowed.clone(),
            ReadScope::Entity {
                id: EntityId::new("project_denied"),
            },
        ];

        let grants = AuthorizeClientService::new(&repository)
            .execute(requested)
            .expect("active member should authorize");

        assert_eq!(grants.read.scopes, vec![allowed.clone()]);
        assert_eq!(grants.write.scopes, vec![allowed]);
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
            scopes: Vec::new(),
        };

        let error = AuthorizeClientService::new(&repository)
            .execute(command())
            .expect_err("removed member should be denied");

        assert_eq!(error, ApplicationError::AccessDenied);
    }
}
