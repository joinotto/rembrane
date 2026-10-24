use std::error::Error;
use std::fmt::{self, Display};

use crate::{
    ActivityId, ContextPackId, DisclosureId, EventId, EvidenceId, MemoryId, PrincipalId,
    WorkspaceId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
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
    ObservationCaptured {
        evidence_id: EvidenceId,
    },
    ActivityCheckpointed {
        activity_id: ActivityId,
        version: u64,
    },
    DisclosureRecorded {
        disclosure_id: DisclosureId,
        context_pack_id: ContextPackId,
    },
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEvent {
    id: EventId,
    workspace_id: WorkspaceId,
    actor_id: PrincipalId,
    subject_id: Option<PrincipalId>,
    sequence: u64,
    payload: EventPayload,
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
    use crate::{EventId, MemoryId, PrincipalId, WorkspaceId};

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
}
