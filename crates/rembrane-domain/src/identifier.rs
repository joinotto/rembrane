use std::fmt::{self, Display};

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"<redacted>")
                    .finish()
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
identifier!(AdministrativeAuditEventId);
identifier!(BookingResearchId);
identifier!(CheckpointId);
identifier!(ClientId);
identifier!(ContextPackId);
identifier!(DisclosureId);
identifier!(EntityId);
identifier!(EventId);
identifier!(EvidenceId);
identifier!(InvitationId);
identifier!(KnowledgeEdgeId);
identifier!(KnowledgeNodeId);
identifier!(LegalHoldId);
identifier!(MemoryId);
identifier!(PrincipalId);
identifier!(ProjectionJobId);
identifier!(ProviderId);
identifier!(KeyRotationId);
identifier!(TripConstraintId);
identifier!(TripDecisionId);
identifier!(TripParticipantId);
identifier!(ShareProposalId);
identifier!(WorkspaceId);

#[cfg(test)]
mod tests {
    use super::{ProviderId, WorkspaceId};

    #[test]
    fn identifier_preserves_opaque_value() {
        let identifier = WorkspaceId::new("workspace_01");

        assert_eq!(identifier.as_str(), "workspace_01");
        assert_eq!(identifier.to_string(), "workspace_01");
    }

    #[test]
    fn identifier_debug_output_is_redacted_without_changing_display() {
        let workspace = WorkspaceId::new("private_workspace");
        let provider = ProviderId::new("private.provider");

        let diagnostic = format!("{workspace:?} {provider:?}");

        assert!(!diagnostic.contains("private_workspace"));
        assert!(!diagnostic.contains("private.provider"));
        assert!(diagnostic.contains("WorkspaceId(\"<redacted>\")"));
        assert!(diagnostic.contains("ProviderId(\"<redacted>\")"));
        assert_eq!(workspace.to_string(), "private_workspace");
        assert_eq!(provider.to_string(), "private.provider");
    }
}
