use crate::{ActivityId, ClientId, EntityId, MemoryScope, PrincipalId, WorkspaceId};

/// A scope a client may read. Global means global memories only; it is not a
/// wildcard over every entity and activity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadScope {
    Global,
    Domain { name: String },
    Entity { id: EntityId },
    Activity { id: ActivityId },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadGrant {
    pub client_id: ClientId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub scopes: Vec<ReadScope>,
    pub permissions: Vec<ReadPermission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadPermission {
    RevealTravelSourceReferences,
    RevealTravelSensitiveProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritePermission {
    CreateMemory,
    ProposeMemory,
    ConfirmMemory,
    ReviseMemory,
    DeleteMemory,
    ShareMemory,
    WriteCheckpoint,
    CreateTrip,
    ReviseTrip,
    CaptureBookingResearch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteGrant {
    pub client_id: ClientId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub scopes: Vec<ReadScope>,
    pub permissions: Vec<WritePermission>,
}

impl WriteGrant {
    #[must_use]
    pub fn allows(&self, permission: WritePermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn allows_scope(&self, memory_scope: &MemoryScope) -> bool {
        scope_is_allowed(&self.scopes, memory_scope)
    }
}

impl ReadGrant {
    #[must_use]
    pub fn allows(&self, memory_scope: &MemoryScope) -> bool {
        scope_is_allowed(&self.scopes, memory_scope)
    }

    #[must_use]
    pub fn allows_permission(&self, permission: ReadPermission) -> bool {
        self.permissions.contains(&permission)
    }
}

fn scope_is_allowed(scopes: &[ReadScope], memory_scope: &MemoryScope) -> bool {
    scopes.iter().any(|scope| match (scope, memory_scope) {
        (ReadScope::Global, MemoryScope::Global) => true,
        (ReadScope::Domain { name: allowed }, MemoryScope::Domain { name: requested }) => {
            allowed == requested
        }
        (ReadScope::Entity { id: allowed }, MemoryScope::Entity { id: requested }) => {
            allowed == requested
        }
        (ReadScope::Activity { id: allowed }, MemoryScope::Activity { id: requested }) => {
            allowed == requested
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::{ReadGrant, ReadPermission, ReadScope, WriteGrant, WritePermission};
    use crate::{ClientId, EntityId, MemoryScope, PrincipalId, WorkspaceId};

    #[test]
    fn global_permission_is_not_an_all_memory_wildcard() {
        let grant = ReadGrant {
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            scopes: vec![ReadScope::Global],
            permissions: Vec::new(),
        };

        assert!(grant.allows(&MemoryScope::Global));
        assert!(!grant.allows(&MemoryScope::Entity {
            id: EntityId::new("project_01"),
        }));
        assert!(!grant.allows_permission(ReadPermission::RevealTravelSourceReferences));
    }

    #[test]
    fn write_permission_does_not_expand_scope_authority() {
        let grant = WriteGrant {
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            scopes: vec![ReadScope::Global],
            permissions: vec![WritePermission::CreateMemory],
        };

        assert!(grant.allows(WritePermission::CreateMemory));
        assert!(grant.allows_scope(&MemoryScope::Global));
        assert!(!grant.allows_scope(&MemoryScope::Entity {
            id: EntityId::new("project_01"),
        }));
    }
}
