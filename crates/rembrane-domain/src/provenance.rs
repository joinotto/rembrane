use std::fmt;

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
#[derive(Clone, Eq, PartialEq)]
pub struct EvidenceReference {
    pub id: EvidenceId,
    pub source: EvidenceSource,
}

impl fmt::Debug for EvidenceReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvidenceReference")
            .field("id", &"<redacted>")
            .field("source", &self.source)
            .finish()
    }
}

impl EvidenceReference {
    #[must_use]
    pub fn new(id: EvidenceId, source: EvidenceSource) -> Self {
        Self { id, source }
    }
}

#[cfg(test)]
mod tests {
    use super::{EvidenceReference, EvidenceSource};
    use crate::EvidenceId;

    #[test]
    fn debug_output_redacts_evidence_identity() {
        let evidence = EvidenceReference::new(
            EvidenceId::new("private_evidence"),
            EvidenceSource::UserStatement,
        );

        let diagnostic = format!("{evidence:?}");

        assert!(!diagnostic.contains("private_evidence"));
        assert!(diagnostic.contains("source: UserStatement"));
    }
}
