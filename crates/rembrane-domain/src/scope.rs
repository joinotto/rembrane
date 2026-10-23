use crate::{ActivityId, EntityId};

/// Determines where a memory is valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryScope {
    Global,
    Domain { name: String },
    Entity { id: EntityId },
    Activity { id: ActivityId },
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
    use crate::ActivityId;

    #[test]
    fn activity_is_more_specific_than_global_scope() {
        let activity = MemoryScope::Activity {
            id: ActivityId::new("activity_01"),
        };

        assert!(activity.specificity() > MemoryScope::Global.specificity());
    }
}
