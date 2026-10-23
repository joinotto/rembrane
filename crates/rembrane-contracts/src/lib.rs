//! Transport-independent request and response contracts.

use rembrane_domain::{
    ActivityId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId,
    MemoryRecord, PrincipalId, WorkspaceId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextRequest {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub domain: Option<String>,
    pub entity_id: Option<EntityId>,
    pub activity_id: Option<ActivityId>,
    pub purpose: String,
    pub query: String,
    pub maximum_items: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextResponse {
    pub items: Vec<MemoryRecord>,
    pub context_pack_id: ContextPackId,
    pub disclosure_id: DisclosureId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDisclosureRequest {
    pub receipt: DisclosureReceipt,
}
