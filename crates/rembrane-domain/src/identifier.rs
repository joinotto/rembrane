use std::fmt::{self, Display};

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }
    };
}

identifier!(ActivityId);
identifier!(BookingResearchId);
identifier!(CheckpointId);
identifier!(ClientId);
identifier!(ContextPackId);
identifier!(DisclosureId);
identifier!(EntityId);
identifier!(EventId);
identifier!(EvidenceId);
identifier!(InvitationId);
identifier!(MemoryId);
identifier!(PrincipalId);
identifier!(ProjectionJobId);
identifier!(ProviderId);
identifier!(TripConstraintId);
identifier!(TripDecisionId);
identifier!(TripParticipantId);
identifier!(ShareProposalId);
identifier!(WorkspaceId);

#[cfg(test)]
mod tests {
    use super::WorkspaceId;

    #[test]
    fn identifier_preserves_opaque_value() {
        let identifier = WorkspaceId::new("workspace_01");

        assert_eq!(identifier.as_str(), "workspace_01");
        assert_eq!(identifier.to_string(), "workspace_01");
    }
}
