use crate::{
    ClientId, ContextPackId, DisclosureId, MemoryId, PrincipalId, WorkspaceId,
};

/// Identifies the exact memory revision disclosed to a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosedMemory {
    pub id: MemoryId,
    pub version: u64,
}

/// An append-only audit record created when memory crosses a trust boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisclosureReceipt {
    pub id: DisclosureId,
    pub context_pack_id: ContextPackId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub purpose: String,
    pub memories: Vec<DisclosedMemory>,
}

impl DisclosureReceipt {
    #[must_use]
    pub fn contains(&self, memory_id: &MemoryId, version: u64) -> bool {
        self.memories
            .iter()
            .any(|memory| &memory.id == memory_id && memory.version == version)
    }
}

#[cfg(test)]
mod tests {
    use super::{DisclosedMemory, DisclosureReceipt};
    use crate::{
        ClientId, ContextPackId, DisclosureId, MemoryId, PrincipalId,
        WorkspaceId,
    };

    #[test]
    fn receipt_tracks_exact_memory_version() {
        let memory_id = MemoryId::new("memory_01");
        let receipt = DisclosureReceipt {
            id: DisclosureId::new("disclosure_01"),
            context_pack_id: ContextPackId::new("context_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_01"),
            purpose: "assistant_personalization".to_owned(),
            memories: vec![DisclosedMemory {
                id: memory_id.clone(),
                version: 3,
            }],
        };

        assert!(receipt.contains(&memory_id, 3));
        assert!(!receipt.contains(&memory_id, 2));
    }
}
