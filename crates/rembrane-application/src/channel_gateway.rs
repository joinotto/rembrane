use std::collections::BTreeMap;

use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};

use crate::ApplicationError;

pub struct ChannelReplayGuard {
    accepted: BTreeMap<(ChannelKind, String), u64>,
    maximum_events: usize,
    replay_window_seconds: u64,
}

impl ChannelReplayGuard {
    /// Creates a bounded replay guard for authenticated channel events.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or replay window.
    pub fn new(
        maximum_events: usize,
        replay_window_seconds: u64,
    ) -> Result<Self, ApplicationError> {
        if maximum_events == 0 || replay_window_seconds == 0 {
            return Err(ApplicationError::Validation(
                "channel replay limits must be positive".to_owned(),
            ));
        }
        Ok(Self {
            accepted: BTreeMap::new(),
            maximum_events,
            replay_window_seconds,
        })
    }

    /// Accepts one authenticated event exactly once within the configured
    /// replay window.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` for replay, `Validation` for a future receipt
    /// time, and `StorageUnavailable` when bounded capacity is exhausted.
    pub fn accept(
        &mut self,
        message: &VerifiedChannelMessage,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        if message.received_at_epoch_seconds() > now_epoch_seconds {
            return Err(ApplicationError::Validation(
                "channel event receipt time is in the future".to_owned(),
            ));
        }
        let oldest = now_epoch_seconds.saturating_sub(self.replay_window_seconds);
        self.accepted
            .retain(|_, accepted_at| *accepted_at >= oldest);
        let key = (message.channel(), message.event_id().to_owned());
        if self.accepted.contains_key(&key) {
            return Err(ApplicationError::AlreadyExists);
        }
        if self.accepted.len() >= self.maximum_events {
            return Err(ApplicationError::StorageUnavailable);
        }
        self.accepted.insert(key, now_epoch_seconds);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::ChannelReplayGuard;
    use crate::ApplicationError;

    fn message(channel: ChannelKind, id: &str, received_at: u64) -> VerifiedChannelMessage {
        VerifiedChannelMessage::from_authenticated_transport(
            channel,
            id,
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_01"),
            "continue",
            received_at,
        )
        .expect("fixture should be valid")
    }

    #[test]
    fn rejects_replay_future_time_and_capacity_exhaustion() {
        let mut guard = ChannelReplayGuard::new(1, 100).expect("guard should be valid");
        let first = message(ChannelKind::WhatsAppBusiness, "event_01", 1_000);
        guard
            .accept(&first, 1_000)
            .expect("first event should pass");
        assert_eq!(
            guard.accept(&first, 1_001).expect_err("replay must fail"),
            ApplicationError::AlreadyExists
        );
        assert_eq!(
            guard
                .accept(
                    &message(ChannelKind::WhatsAppBusiness, "event_02", 1_001),
                    1_001
                )
                .expect_err("capacity must fail closed"),
            ApplicationError::StorageUnavailable
        );
        assert!(matches!(
            guard.accept(
                &message(ChannelKind::WhatsAppBusiness, "event_03", 2_000),
                1_999
            ),
            Err(ApplicationError::Validation(_))
        ));
        guard
            .accept(
                &message(ChannelKind::WhatsAppBusiness, "event_04", 1_101),
                1_101,
            )
            .expect("expired replay entry should release capacity");
    }

    #[test]
    fn channel_namespace_prevents_cross_platform_identifier_collision() {
        let mut guard = ChannelReplayGuard::new(2, 100).expect("guard should be valid");
        guard
            .accept(
                &message(ChannelKind::WhatsAppBusiness, "event_01", 1_000),
                1_000,
            )
            .expect("WhatsApp event should pass");
        guard
            .accept(
                &message(ChannelKind::IMessageExtension, "event_01", 1_000),
                1_000,
            )
            .expect("same opaque id on another channel should pass");
    }
}
