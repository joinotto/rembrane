use rembrane_domain::{
    DisclosureReceipt, MemoryId, MemoryRecord, PrincipalId, WorkspaceId,
};

use crate::ApplicationError;

pub trait MemoryRepository {
    fn insert(&mut self, memory: MemoryRecord) -> Result<(), ApplicationError>;

    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError>;

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError>;

    fn replace(
        &mut self,
        memory: MemoryRecord,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait DisclosureRepository {
    fn append(
        &mut self,
        receipt: DisclosureReceipt,
    ) -> Result<(), ApplicationError>;
}
