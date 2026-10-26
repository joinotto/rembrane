use std::fmt;

use crate::{ActivityId, EntityId};

/// Determines where a memory is valid.
#[derive(Clone, Eq, PartialEq)]
pub enum MemoryScope {
    Global,
    Domain { name: String },
    Entity { id: EntityId },
    Activity { id: ActivityId },
}

impl fmt::Debug for MemoryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Global => "global",
            Self::Domain { .. } => "domain",
            Self::Entity { .. } => "entity",
            Self::Activity { .. } => "activity",
        };
        formatter
            .debug_struct("MemoryScope")
            .field("kind", &kind)
            .finish()
    }
}

impl MemoryScope {
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Domain { .. } => 1,
            Self::Entity { .. } => 2,
            Self::Activity { .. } => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryScope;
    use crate::{ActivityId, EntityId};

    #[test]
    fn activity_is_more_specific_than_global_scope() {
        let activity = MemoryScope::Activity {
            id: ActivityId::new("activity_01"),
        };

        assert!(activity.specificity() > MemoryScope::Global.specificity());
    }

    #[test]
    fn debug_output_redacts_scope_selectors() {
        let domain = MemoryScope::Domain {
            name: "private_domain".to_owned(),
        };
        let entity = MemoryScope::Entity {
            id: EntityId::new("private_entity"),
        };

        let diagnostic = format!("{domain:?} {entity:?}");

        assert!(!diagnostic.contains("private_domain"));
        assert!(!diagnostic.contains("private_entity"));
        assert!(diagnostic.contains("kind: \"domain\""));
        assert!(diagnostic.contains("kind: \"entity\""));
    }
}
