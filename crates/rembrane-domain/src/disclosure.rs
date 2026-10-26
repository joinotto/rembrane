use std::fmt;

use crate::{
    ActivityId, BookingResearchId, CheckpointId, ClientId, ContextPackId, DisclosureId, EntityId,
    KnowledgeEdgeId, KnowledgeNodeId, MemoryId, PrincipalId, ResearchFreshness, WorkspaceId,
};

/// Identifies the exact memory revision disclosed to a client.
#[derive(Clone, Eq, PartialEq)]
pub struct DisclosedMemory {
    pub id: MemoryId,
    pub version: u64,
}

impl fmt::Debug for DisclosedMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosedMemory")
            .field("id", &"<redacted>")
            .field("version", &self.version)
            .finish()
    }
}

/// Append-only audit record for one activity-checkpoint revision disclosed.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckpointDisclosureReceipt {
    pub id: DisclosureId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub purpose: String,
    pub checkpoint_id: CheckpointId,
    pub checkpoint_version: u64,
    pub activity_id: ActivityId,
}

impl fmt::Debug for CheckpointDisclosureReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckpointDisclosureReceipt")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("subject_id", &"<redacted>")
            .field("client_id", &"<redacted>")
            .field("purpose", &"<redacted>")
            .field("checkpoint_id", &"<redacted>")
            .field("checkpoint_version", &self.checkpoint_version)
            .field("activity_id", &"<redacted>")
            .finish()
    }
}

/// Identifies the exact booking-research revision and freshness classification disclosed.
#[derive(Clone, Eq, PartialEq)]
pub struct DisclosedBookingResearch {
    pub id: BookingResearchId,
    pub version: u64,
    pub freshness: ResearchFreshness,
}

impl fmt::Debug for DisclosedBookingResearch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosedBookingResearch")
            .field("id", &"<redacted>")
            .field("version", &self.version)
            .field("freshness", &self.freshness)
            .finish()
    }
}

/// Append-only audit record for one exact-trip travel context disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct TravelDisclosureReceipt {
    pub id: DisclosureId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub purpose: String,
    pub trip_id: EntityId,
    pub trip_version: u64,
    pub as_of: String,
    pub source_references_included: bool,
    pub sensitive_profile_included: bool,
    pub research: Vec<DisclosedBookingResearch>,
}

impl fmt::Debug for TravelDisclosureReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TravelDisclosureReceipt")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("subject_id", &"<redacted>")
            .field("client_id", &"<redacted>")
            .field("purpose", &"<redacted>")
            .field("trip_id", &"<redacted>")
            .field("trip_version", &self.trip_version)
            .field("as_of", &"<redacted>")
            .field(
                "source_references_included",
                &self.source_references_included,
            )
            .field(
                "sensitive_profile_included",
                &self.sensitive_profile_included,
            )
            .field("research_count", &self.research.len())
            .finish()
    }
}

/// Identifies the exact canonical knowledge-edge revision disclosed.
#[derive(Clone, Eq, PartialEq)]
pub struct DisclosedKnowledgeEdge {
    pub id: KnowledgeEdgeId,
    pub version: u64,
}

impl fmt::Debug for DisclosedKnowledgeEdge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosedKnowledgeEdge")
            .field("id", &"<redacted>")
            .field("version", &self.version)
            .finish()
    }
}

/// Direction used for an audited graph-context disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphDisclosureDirection {
    Incoming,
    Outgoing,
    Both,
}

/// Append-only audit record for one canonical graph-context disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct GraphDisclosureReceipt {
    pub id: DisclosureId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub purpose: String,
    pub node_id: KnowledgeNodeId,
    pub direction: GraphDisclosureDirection,
    pub valid_at_epoch_seconds: u64,
    pub edges: Vec<DisclosedKnowledgeEdge>,
}

impl fmt::Debug for GraphDisclosureReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphDisclosureReceipt")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("subject_id", &"<redacted>")
            .field("client_id", &"<redacted>")
            .field("purpose", &"<redacted>")
            .field("node_id", &"<redacted>")
            .field("direction", &self.direction)
            .field("valid_at_epoch_seconds", &"<redacted>")
            .field("edge_count", &self.edges.len())
            .finish()
    }
}

/// An append-only audit record created when memory crosses a trust boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct DisclosureReceipt {
    pub id: DisclosureId,
    pub context_pack_id: ContextPackId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub purpose: String,
    pub memories: Vec<DisclosedMemory>,
}

impl fmt::Debug for DisclosureReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureReceipt")
            .field("id", &"<redacted>")
            .field("context_pack_id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("subject_id", &"<redacted>")
            .field("client_id", &"<redacted>")
            .field("purpose", &"<redacted>")
            .field("memory_count", &self.memories.len())
            .finish()
    }
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
    use super::{
        CheckpointDisclosureReceipt, DisclosedBookingResearch, DisclosedKnowledgeEdge,
        DisclosedMemory, DisclosureReceipt, GraphDisclosureDirection, GraphDisclosureReceipt,
        TravelDisclosureReceipt,
    };
    use crate::{
        ActivityId, BookingResearchId, CheckpointId, ClientId, ContextPackId, DisclosureId,
        EntityId, KnowledgeEdgeId, KnowledgeNodeId, MemoryId, PrincipalId, ResearchFreshness,
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

    #[test]
    fn debug_output_redacts_disclosure_routing_purpose_and_timeline() {
        let checkpoint = CheckpointDisclosureReceipt {
            id: DisclosureId::new("private_checkpoint_disclosure"),
            workspace_id: WorkspaceId::new("private_workspace"),
            subject_id: PrincipalId::new("private_subject"),
            client_id: ClientId::new("private_client"),
            purpose: "private_checkpoint_purpose".to_owned(),
            checkpoint_id: CheckpointId::new("private_checkpoint"),
            checkpoint_version: 4,
            activity_id: ActivityId::new("private_activity"),
        };
        let travel = TravelDisclosureReceipt {
            id: DisclosureId::new("private_travel_disclosure"),
            workspace_id: WorkspaceId::new("private_workspace"),
            subject_id: PrincipalId::new("private_subject"),
            client_id: ClientId::new("private_client"),
            purpose: "private_travel_purpose".to_owned(),
            trip_id: EntityId::new("private_trip"),
            trip_version: 5,
            as_of: "2028-07-03T12:34:56Z".to_owned(),
            source_references_included: true,
            sensitive_profile_included: false,
            research: vec![DisclosedBookingResearch {
                id: BookingResearchId::new("private_research"),
                version: 6,
                freshness: ResearchFreshness::Fresh,
            }],
        };
        let graph = GraphDisclosureReceipt {
            id: DisclosureId::new("private_graph_disclosure"),
            workspace_id: WorkspaceId::new("private_workspace"),
            subject_id: PrincipalId::new("private_subject"),
            client_id: ClientId::new("private_client"),
            purpose: "private_graph_purpose".to_owned(),
            node_id: KnowledgeNodeId::new("private_node"),
            direction: GraphDisclosureDirection::Outgoing,
            valid_at_epoch_seconds: 1_900_123_456,
            edges: vec![DisclosedKnowledgeEdge {
                id: KnowledgeEdgeId::new("private_edge"),
                version: 7,
            }],
        };
        let memory = DisclosureReceipt {
            id: DisclosureId::new("private_memory_disclosure"),
            context_pack_id: ContextPackId::new("private_context_pack"),
            workspace_id: WorkspaceId::new("private_workspace"),
            subject_id: PrincipalId::new("private_subject"),
            client_id: ClientId::new("private_client"),
            purpose: "private_memory_purpose".to_owned(),
            memories: vec![DisclosedMemory {
                id: MemoryId::new("private_memory"),
                version: 8,
            }],
        };

        let diagnostic = format!("{checkpoint:?} {travel:?} {graph:?} {memory:?}");

        for private_value in [
            "private_checkpoint_disclosure",
            "private_workspace",
            "private_subject",
            "private_client",
            "private_checkpoint_purpose",
            "private_checkpoint",
            "private_activity",
            "private_travel_disclosure",
            "private_travel_purpose",
            "private_trip",
            "2028-07-03T12:34:56Z",
            "private_research",
            "private_graph_disclosure",
            "private_graph_purpose",
            "private_node",
            "1900123456",
            "private_edge",
            "private_memory_disclosure",
            "private_context_pack",
            "private_memory_purpose",
            "private_memory",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("checkpoint_version: 4"));
        assert!(diagnostic.contains("trip_version: 5"));
        assert!(diagnostic.contains("research_count: 1"));
        assert!(diagnostic.contains("direction: Outgoing"));
        assert!(diagnostic.contains("edge_count: 1"));
        assert!(diagnostic.contains("memory_count: 1"));
    }
}
