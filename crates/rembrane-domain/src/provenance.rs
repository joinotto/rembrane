use crate::EvidenceId;

/// The class of source from which a memory was derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceSource {
    UserStatement,
    AgentObservation,
    ToolResult,
    ImportedRecord,
    WorkspaceDecision,
}

/// A reference to immutable evidence held by the canonical event ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceReference {
    pub id: EvidenceId,
    pub source: EvidenceSource,
}

impl EvidenceReference {
    #[must_use]
    pub fn new(id: EvidenceId, source: EvidenceSource) -> Self {
        Self { id, source }
    }
}
