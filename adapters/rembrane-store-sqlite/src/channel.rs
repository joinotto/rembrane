use rembrane_application::{ApplicationError, ChannelReplayRepository};
use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
use rusqlite::{TransactionBehavior, params};

use crate::{SqliteStore, map_write_error};

impl<C> ChannelReplayRepository for SqliteStore<C> {
    fn accept_channel_event(
        &mut self,
        message: &VerifiedChannelMessage,
        now_epoch_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<(), ApplicationError> {
        if message.received_at_epoch_seconds() > now_epoch_seconds {
            return Err(ApplicationError::Validation(
                "channel event receipt time is in the future".to_owned(),
            ));
        }
        if replay_window_seconds == 0 || maximum_events == 0 {
            return Err(ApplicationError::Validation(
                "channel replay limits must be positive".to_owned(),
            ));
        }
        let expires_at_epoch_seconds = now_epoch_seconds
            .checked_add(replay_window_seconds)
            .ok_or_else(|| {
                ApplicationError::Validation("channel replay expiry overflows".to_owned())
            })?;

        // IMMEDIATE obtains the single SQLite writer before cleanup, capacity
        // enforcement, and insertion so multiple processes cannot over-admit.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "DELETE FROM channel_event_receipts
                 WHERE expires_at_epoch_seconds <= ?1",
                [now_epoch_seconds],
            )
            .map_err(map_write_error)?;

        let accepted_events: u64 = transaction
            .query_row("SELECT count(*) FROM channel_event_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if accepted_events >= maximum_events as u64 {
            return Err(ApplicationError::StorageUnavailable);
        }

        transaction
            .execute(
                "INSERT INTO channel_event_receipts (
                    channel, event_id, workspace_id,
                    accepted_at_epoch_seconds, expires_at_epoch_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    encode_channel(message.channel()),
                    message.event_id(),
                    message.workspace_id().as_str(),
                    now_epoch_seconds,
                    expires_at_epoch_seconds,
                ],
            )
            .map_err(map_write_error)?;
        transaction.commit().map_err(map_write_error)
    }
}

const fn encode_channel(channel: ChannelKind) -> &'static str {
    match channel {
        ChannelKind::WhatsAppBusiness => "whatsapp-business",
        ChannelKind::IMessageExtension => "imessage-extension",
        ChannelKind::MobileShare => "mobile-share",
    }
}

#[cfg(test)]
mod tests {
    use rembrane_application::{ApplicationError, ChannelReplayRepository, WorkspaceRepository};
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, Workspace, WorkspaceId};

    use crate::SqliteStore;

    fn message(
        channel: ChannelKind,
        event_id: &str,
        workspace_id: &str,
        received_at: u64,
    ) -> VerifiedChannelMessage {
        VerifiedChannelMessage::from_authenticated_transport(
            channel,
            event_id,
            WorkspaceId::new(workspace_id),
            PrincipalId::new("principal_01"),
            ClientId::new("client_01"),
            "continue",
            received_at,
        )
        .expect("fixture should be valid")
    }

    fn store() -> SqliteStore {
        let mut store = SqliteStore::open_in_memory().expect("store should initialize");
        for id in ["workspace_01", "workspace_02"] {
            store
                .insert_workspace(Workspace::personal(WorkspaceId::new(id)))
                .expect("workspace should persist");
        }
        store
    }

    #[test]
    fn atomically_rejects_cross_workspace_replay_without_storing_content() {
        let mut store = store();
        store
            .accept_channel_event(
                &message(
                    ChannelKind::WhatsAppBusiness,
                    "event_01",
                    "workspace_01",
                    1_000,
                ),
                1_000,
                100,
                10,
            )
            .expect("first event should pass");
        assert_eq!(
            store
                .accept_channel_event(
                    &message(
                        ChannelKind::WhatsAppBusiness,
                        "event_01",
                        "workspace_02",
                        1_001,
                    ),
                    1_001,
                    100,
                    10,
                )
                .expect_err("cross-workspace replay must fail"),
            ApplicationError::AlreadyExists
        );
        let columns: Vec<String> = store
            .connection
            .prepare("PRAGMA table_info(channel_event_receipts)")
            .expect("schema should inspect")
            .query_map([], |row| row.get(1))
            .expect("columns should query")
            .collect::<Result<_, _>>()
            .expect("columns should decode");
        assert!(!columns.iter().any(|column| {
            matches!(
                column.as_str(),
                "text" | "content" | "principal_id" | "client_id"
            )
        }));
    }

    #[test]
    fn expiry_channel_namespace_and_capacity_are_enforced() {
        let mut store = store();
        store
            .accept_channel_event(
                &message(
                    ChannelKind::WhatsAppBusiness,
                    "event_01",
                    "workspace_01",
                    1_000,
                ),
                1_000,
                100,
                1,
            )
            .expect("first event should pass");
        assert_eq!(
            store
                .accept_channel_event(
                    &message(
                        ChannelKind::WhatsAppBusiness,
                        "event_02",
                        "workspace_01",
                        1_001,
                    ),
                    1_001,
                    100,
                    1,
                )
                .expect_err("capacity must fail closed"),
            ApplicationError::StorageUnavailable
        );
        store
            .accept_channel_event(
                &message(
                    ChannelKind::IMessageExtension,
                    "event_01",
                    "workspace_02",
                    1_100,
                ),
                1_100,
                100,
                1,
            )
            .expect("expired receipt should be purged and channel namespace accepted");
    }
}
