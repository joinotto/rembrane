use std::error::Error;
use std::fmt::{self, Display};

use crate::{
    ActivityId, BookingResearchId, ContextPackId, DisclosureId, EntityId, EventId, EvidenceId,
    MemoryId, PrincipalId, ShareProposalId, WorkspaceId,
};

#[derive(Clone, Eq, PartialEq)]
pub enum EventPayload {
    MemoryProposed {
        memory_id: MemoryId,
        version: u64,
    },
    MemoryConfirmed {
        memory_id: MemoryId,
        version: u64,
    },
    MemoryCreated {
        memory_id: MemoryId,
        version: u64,
    },
    MemoryRevised {
        memory_id: MemoryId,
        version: u64,
    },
    MemoryDeleted {
        memory_id: MemoryId,
        version: u64,
    },
    MemoryShareProposed {
        proposal_id: ShareProposalId,
        source_memory_id: MemoryId,
        source_version: u64,
        target_workspace_id: WorkspaceId,
    },
    MemoryShareApproved {
        proposal_id: ShareProposalId,
        target_workspace_id: WorkspaceId,
        target_memory_id: MemoryId,
    },
    MemoryShareRejected {
        proposal_id: ShareProposalId,
    },
    MemoryShareRevoked {
        proposal_id: ShareProposalId,
    },
    MemorySharedIn {
        proposal_id: ShareProposalId,
        source_workspace_id: WorkspaceId,
        source_memory_id: MemoryId,
        source_version: u64,
        target_memory_id: MemoryId,
        target_version: u64,
    },
    ObservationCaptured {
        evidence_id: EvidenceId,
    },
    ActivityCheckpointed {
        activity_id: ActivityId,
        version: u64,
    },
    TripCreated {
        trip_id: EntityId,
        version: u64,
    },
    TripRevised {
        trip_id: EntityId,
        version: u64,
    },
    BookingResearchCaptured {
        research_id: BookingResearchId,
        trip_id: EntityId,
        version: u64,
    },
    DisclosureRecorded {
        disclosure_id: DisclosureId,
        context_pack_id: ContextPackId,
    },
}

impl EventPayload {
    const fn diagnostic_kind(&self) -> &'static str {
        match self {
            Self::MemoryProposed { .. } => "memory-proposed",
            Self::MemoryConfirmed { .. } => "memory-confirmed",
            Self::MemoryCreated { .. } => "memory-created",
            Self::MemoryRevised { .. } => "memory-revised",
            Self::MemoryDeleted { .. } => "memory-deleted",
            Self::MemoryShareProposed { .. } => "memory-share-proposed",
            Self::MemoryShareApproved { .. } => "memory-share-approved",
            Self::MemoryShareRejected { .. } => "memory-share-rejected",
            Self::MemoryShareRevoked { .. } => "memory-share-revoked",
            Self::MemorySharedIn { .. } => "memory-shared-in",
            Self::ObservationCaptured { .. } => "observation-captured",
            Self::ActivityCheckpointed { .. } => "activity-checkpointed",
            Self::TripCreated { .. } => "trip-created",
            Self::TripRevised { .. } => "trip-revised",
            Self::BookingResearchCaptured { .. } => "booking-research-captured",
            Self::DisclosureRecorded { .. } => "disclosure-recorded",
        }
    }

    const fn diagnostic_versions(&self) -> (Option<u64>, Option<u64>) {
        match self {
            Self::MemoryProposed { version, .. }
            | Self::MemoryConfirmed { version, .. }
            | Self::MemoryCreated { version, .. }
            | Self::MemoryRevised { version, .. }
            | Self::MemoryDeleted { version, .. }
            | Self::ActivityCheckpointed { version, .. }
            | Self::TripCreated { version, .. }
            | Self::TripRevised { version, .. }
            | Self::BookingResearchCaptured { version, .. } => (Some(*version), None),
            Self::MemoryShareProposed { source_version, .. } => (Some(*source_version), None),
            Self::MemorySharedIn {
                source_version,
                target_version,
                ..
            } => (Some(*source_version), Some(*target_version)),
            Self::MemoryShareApproved { .. }
            | Self::MemoryShareRejected { .. }
            | Self::MemoryShareRevoked { .. }
            | Self::ObservationCaptured { .. }
            | Self::DisclosureRecorded { .. } => (None, None),
        }
    }
}

impl fmt::Debug for EventPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (primary_version, secondary_version) = self.diagnostic_versions();
        formatter
            .debug_struct("EventPayload")
            .field("kind", &self.diagnostic_kind())
            .field("primary_version", &primary_version)
            .field("secondary_version", &secondary_version)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    InvalidSequence,
}

impl Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSequence => {
                formatter.write_str("event sequence must be greater than zero")
            }
        }
    }
}

impl Error for EventError {}

/// An immutable fact in a workspace event stream.
#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalEvent {
    id: EventId,
    workspace_id: WorkspaceId,
    actor_id: PrincipalId,
    subject_id: Option<PrincipalId>,
    sequence: u64,
    payload: EventPayload,
}

impl fmt::Debug for CanonicalEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalEvent")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("actor_id", &"<redacted>")
            .field("subject_id_present", &self.subject_id.is_some())
            .field("sequence", &self.sequence)
            .field("payload", &self.payload)
            .finish()
    }
}

impl CanonicalEvent {
    pub fn new(
        id: EventId,
        workspace_id: WorkspaceId,
        actor_id: PrincipalId,
        subject_id: Option<PrincipalId>,
        sequence: u64,
        payload: EventPayload,
    ) -> Result<Self, EventError> {
        if sequence == 0 {
            return Err(EventError::InvalidSequence);
        }

        Ok(Self {
            id,
            workspace_id,
            actor_id,
            subject_id,
            sequence,
            payload,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &EventId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn actor_id(&self) -> &PrincipalId {
        &self.actor_id
    }

    #[must_use]
    pub const fn subject_id(&self) -> Option<&PrincipalId> {
        self.subject_id.as_ref()
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn payload(&self) -> &EventPayload {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalEvent, EventError, EventPayload};
    use crate::{EventId, MemoryId, PrincipalId, ShareProposalId, WorkspaceId};

    #[test]
    fn rejects_zero_sequence() {
        let error = CanonicalEvent::new(
            EventId::new("event_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            None,
            0,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_01"),
                version: 1,
            },
        )
        .expect_err("zero sequence must fail");

        assert_eq!(error, EventError::InvalidSequence);
    }

    #[test]
    fn debug_output_redacts_event_and_payload_identities() {
        let event = CanonicalEvent::new(
            EventId::new("private_event"),
            WorkspaceId::new("private_workspace"),
            PrincipalId::new("private_actor"),
            Some(PrincipalId::new("private_subject")),
            42,
            EventPayload::MemorySharedIn {
                proposal_id: ShareProposalId::new("private_proposal"),
                source_workspace_id: WorkspaceId::new("private_source_workspace"),
                source_memory_id: MemoryId::new("private_source_memory"),
                source_version: 7,
                target_memory_id: MemoryId::new("private_target_memory"),
                target_version: 3,
            },
        )
        .expect("event should validate");

        let diagnostic = format!("{event:?}");

        for private_value in [
            "private_event",
            "private_workspace",
            "private_actor",
            "private_subject",
            "private_proposal",
            "private_source_workspace",
            "private_source_memory",
            "private_target_memory",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("subject_id_present: true"));
        assert!(diagnostic.contains("sequence: 42"));
        assert!(diagnostic.contains("kind: \"memory-shared-in\""));
        assert!(diagnostic.contains("primary_version: Some(7)"));
        assert!(diagnostic.contains("secondary_version: Some(3)"));
    }
}
