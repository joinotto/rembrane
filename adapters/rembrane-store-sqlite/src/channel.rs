use rembrane_application::{
    ApplicationError, ChannelIngressRepository, ChannelReplayRepository,
    ChannelSenderBindingRepository,
};
use rembrane_contracts::{ChannelKind, ChannelSenderBinding, VerifiedChannelMessage};
use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeTargetKind, ClientId,
    PrincipalId, WorkspaceId,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{SqliteStore, insert_administrative_audit, map_write_error};

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

impl<C> ChannelSenderBindingRepository for SqliteStore<C> {
    fn find_channel_sender_binding(
        &self,
        channel: ChannelKind,
        account_lookup_key: &str,
        sender_lookup_key: &str,
    ) -> Result<Option<ChannelSenderBinding>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT workspace_id, principal_id, client_id
                 FROM channel_sender_bindings AS binding
                 WHERE binding.channel = ?1
                   AND binding.account_lookup_key = ?2
                   AND binding.sender_lookup_key = ?3
                   AND EXISTS (
                       SELECT 1
                       FROM memberships AS membership
                       WHERE membership.workspace_id = binding.workspace_id
                         AND membership.principal_id = binding.principal_id
                         AND membership.status = 'active'
                   )",
                params![
                    encode_channel(channel),
                    account_lookup_key,
                    sender_lookup_key
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(workspace_id, principal_id, client_id)| {
                ChannelSenderBinding::new(
                    channel,
                    account_lookup_key,
                    sender_lookup_key,
                    WorkspaceId::new(workspace_id),
                    PrincipalId::new(principal_id),
                    ClientId::new(client_id),
                )
                .map_err(|_| ApplicationError::StorageUnavailable)
            })
            .transpose()
    }

    fn insert_channel_sender_binding(
        &mut self,
        binding: ChannelSenderBinding,
    ) -> Result<(), ApplicationError> {
        self.connection
            .execute(
                "INSERT INTO channel_sender_bindings (
                    channel, account_lookup_key, sender_lookup_key,
                    workspace_id, principal_id, client_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    encode_channel(binding.channel()),
                    binding.account_lookup_key(),
                    binding.sender_lookup_key(),
                    binding.workspace_id().as_str(),
                    binding.principal_id().as_str(),
                    binding.client_id().as_str(),
                ],
            )
            .map_err(map_write_error)?;
        Ok(())
    }

    fn insert_channel_sender_binding_with_audit(
        &mut self,
        binding: ChannelSenderBinding,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_binding_audit(
            &binding,
            &audit_event,
            AdministrativeAction::ChannelBindingCreated,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO channel_sender_bindings (
                    channel, account_lookup_key, sender_lookup_key,
                    workspace_id, principal_id, client_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    encode_channel(binding.channel()),
                    binding.account_lookup_key(),
                    binding.sender_lookup_key(),
                    binding.workspace_id().as_str(),
                    binding.principal_id().as_str(),
                    binding.client_id().as_str(),
                ],
            )
            .map_err(map_write_error)?;
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction.commit().map_err(map_write_error)
    }

    fn delete_channel_sender_binding_with_audit(
        &mut self,
        binding: &ChannelSenderBinding,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_binding_audit(
            binding,
            &audit_event,
            AdministrativeAction::ChannelBindingRevoked,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let deleted = transaction
            .execute(
                "DELETE FROM channel_sender_bindings
                 WHERE channel = ?1
                   AND account_lookup_key = ?2
                   AND sender_lookup_key = ?3
                   AND workspace_id = ?4
                   AND principal_id = ?5
                   AND client_id = ?6",
                params![
                    encode_channel(binding.channel()),
                    binding.account_lookup_key(),
                    binding.sender_lookup_key(),
                    binding.workspace_id().as_str(),
                    binding.principal_id().as_str(),
                    binding.client_id().as_str(),
                ],
            )
            .map_err(map_write_error)?;
        if deleted != 1 {
            return Err(ApplicationError::NotFound);
        }
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction.commit().map_err(map_write_error)
    }
}

impl<C> ChannelIngressRepository for SqliteStore<C> {
    fn accept_bound_channel_event(
        &mut self,
        channel: ChannelKind,
        account_lookup_key: &str,
        sender_lookup_key: &str,
        event_id: &str,
        text: &str,
        received_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<VerifiedChannelMessage, ApplicationError> {
        if received_at_epoch_seconds > now_epoch_seconds {
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let (workspace_id, principal_id, client_id) = transaction
            .query_row(
                "SELECT binding.workspace_id, binding.principal_id, binding.client_id
                 FROM channel_sender_bindings AS binding
                 JOIN memberships AS membership
                   ON membership.workspace_id = binding.workspace_id
                  AND membership.principal_id = binding.principal_id
                  AND membership.status = 'active'
                 WHERE binding.channel = ?1
                   AND binding.account_lookup_key = ?2
                   AND binding.sender_lookup_key = ?3",
                params![
                    encode_channel(channel),
                    account_lookup_key,
                    sender_lookup_key
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .ok_or(ApplicationError::AccessDenied)?;
        let message = VerifiedChannelMessage::from_authenticated_transport(
            channel,
            event_id,
            WorkspaceId::new(workspace_id),
            PrincipalId::new(principal_id),
            ClientId::new(client_id),
            text,
            received_at_epoch_seconds,
        )
        .map_err(|_| ApplicationError::Validation("channel message is invalid".to_owned()))?;
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
        transaction.commit().map_err(map_write_error)?;
        Ok(message)
    }
}

const fn encode_channel(channel: ChannelKind) -> &'static str {
    channel.label()
}

fn validate_binding_audit(
    binding: &ChannelSenderBinding,
    event: &AdministrativeAuditEvent,
    action: AdministrativeAction,
) -> Result<(), ApplicationError> {
    let expected_target = format!(
        "{}:{}:{}",
        binding.channel().label(),
        binding.principal_id().as_str(),
        binding.client_id().as_str()
    );
    if event.workspace_id() != binding.workspace_id()
        || event.action() != action
        || event.target_kind() != AdministrativeTargetKind::ChannelBinding
        || event.target_id() != expected_target
    {
        return Err(ApplicationError::Validation(
            "channel binding audit evidence is invalid".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_application::{
        AdministrativeAuditRepository, ApplicationError, ChannelBindingService,
        ChannelIngressRepository, ChannelReplayRepository, ChannelSenderBindingRepository,
        CreateChannelBindingCommand, MembershipRepository, RevokeChannelBindingCommand,
        WorkspaceRepository,
    };
    use rembrane_contracts::{ChannelKind, ChannelSenderBinding, VerifiedChannelMessage};
    use rembrane_domain::{
        AdministrativeAction, ClientId, Membership, Principal, PrincipalId, Workspace, WorkspaceId,
        WorkspaceRole,
    };

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
        for (workspace, principal) in [
            ("workspace_01", "principal_01"),
            ("workspace_02", "principal_02"),
        ] {
            let workspace_id = WorkspaceId::new(workspace);
            let principal_id = PrincipalId::new(principal);
            store
                .initialize_personal_workspace(
                    Principal::new(principal_id.clone()),
                    Workspace::personal(workspace_id.clone()),
                    Membership::new(workspace_id, principal_id, WorkspaceRole::Owner),
                )
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

    #[test]
    fn sender_binding_is_tenant_scoped_and_revoked_with_membership() {
        let mut store = store();
        let binding = ChannelSenderBinding::new(
            ChannelKind::WhatsAppBusiness,
            "hmac-account-01",
            "hmac-sender-01",
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_whatsapp_01"),
        )
        .expect("binding should be valid");
        store
            .insert_channel_sender_binding(binding.clone())
            .expect("active member binding should persist");
        assert_eq!(
            store
                .find_channel_sender_binding(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-01",
                    "hmac-sender-01",
                )
                .expect("binding lookup should succeed"),
            Some(binding)
        );
        assert!(
            store
                .find_channel_sender_binding(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-02",
                    "hmac-sender-01",
                )
                .expect("other account lookup should succeed")
                .is_none()
        );

        let removed = Membership::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            WorkspaceRole::Owner,
        )
        .remove();
        store
            .replace_membership(removed)
            .expect("membership removal should persist");
        assert!(
            store
                .find_channel_sender_binding(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-01",
                    "hmac-sender-01",
                )
                .expect("revoked binding lookup should succeed")
                .is_none()
        );
    }

    #[test]
    fn administrator_binding_lifecycle_is_atomic_and_audited() {
        let mut store = store();
        let binding = ChannelSenderBinding::new(
            ChannelKind::WhatsAppBusiness,
            "hmac-account-audited",
            "hmac-sender-audited",
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_whatsapp_audited"),
        )
        .expect("binding should be valid");
        ChannelBindingService::new(&mut store)
            .create(CreateChannelBindingCommand {
                binding: binding.clone(),
                created_by: PrincipalId::new("principal_01"),
                request_id: "request_channel_create_01".to_owned(),
            })
            .expect("owner should create binding");
        assert_eq!(
            store
                .list_administrative_audit(&WorkspaceId::new("workspace_01"), 0, 10)
                .expect("audit should load")
                .last()
                .map(rembrane_domain::AdministrativeAuditEvent::action),
            Some(AdministrativeAction::ChannelBindingCreated)
        );

        ChannelBindingService::new(&mut store)
            .revoke(RevokeChannelBindingCommand {
                binding,
                revoked_by: PrincipalId::new("principal_01"),
                request_id: "request_channel_revoke_01".to_owned(),
            })
            .expect("owner should revoke binding");
        assert!(
            store
                .find_channel_sender_binding(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-audited",
                    "hmac-sender-audited",
                )
                .expect("binding lookup should succeed")
                .is_none()
        );
        let audits = store
            .list_administrative_audit(&WorkspaceId::new("workspace_01"), 0, 10)
            .expect("audits should load");
        assert_eq!(audits.len(), 2);
        assert_eq!(
            audits[1].action(),
            AdministrativeAction::ChannelBindingRevoked
        );
    }

    #[test]
    fn sender_binding_rejects_inactive_or_cross_tenant_membership() {
        let mut store = store();
        let removed = Membership::new(
            WorkspaceId::new("workspace_02"),
            PrincipalId::new("principal_02"),
            WorkspaceRole::Owner,
        )
        .remove();
        store
            .replace_membership(removed)
            .expect("membership removal should persist");
        let binding = ChannelSenderBinding::new(
            ChannelKind::WhatsAppBusiness,
            "hmac-account-02",
            "hmac-sender-02",
            WorkspaceId::new("workspace_02"),
            PrincipalId::new("principal_02"),
            ClientId::new("client_whatsapp_02"),
        )
        .expect("binding should be valid");
        assert!(matches!(
            store.insert_channel_sender_binding(binding),
            Err(ApplicationError::Validation(_))
        ));
    }

    #[test]
    fn atomically_resolves_bound_identity_and_reserves_replay() {
        let mut store = store();
        store
            .insert_channel_sender_binding(
                ChannelSenderBinding::new(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-01",
                    "hmac-sender-01",
                    WorkspaceId::new("workspace_01"),
                    PrincipalId::new("principal_01"),
                    ClientId::new("client_whatsapp_01"),
                )
                .expect("binding should be valid"),
            )
            .expect("binding should persist");
        let message = store
            .accept_bound_channel_event(
                ChannelKind::WhatsAppBusiness,
                "hmac-account-01",
                "hmac-sender-01",
                "event_atomic_01",
                "continue",
                1_000,
                1_000,
                100,
                10,
            )
            .expect("bound event should be admitted");
        assert_eq!(message.workspace_id().as_str(), "workspace_01");
        assert_eq!(message.principal_id().as_str(), "principal_01");
        assert_eq!(message.client_id().as_str(), "client_whatsapp_01");
        assert_eq!(
            store
                .accept_bound_channel_event(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-01",
                    "hmac-sender-01",
                    "event_atomic_01",
                    "continue",
                    1_001,
                    1_001,
                    100,
                    10,
                )
                .expect_err("replay must fail"),
            ApplicationError::AlreadyExists
        );
    }

    #[test]
    fn unknown_sender_fails_without_reserving_event_identifier() {
        let mut store = store();
        assert_eq!(
            store
                .accept_bound_channel_event(
                    ChannelKind::WhatsAppBusiness,
                    "unknown-account",
                    "unknown-sender",
                    "event_unknown_01",
                    "continue",
                    1_000,
                    1_000,
                    100,
                    10,
                )
                .expect_err("unknown sender must fail"),
            ApplicationError::AccessDenied
        );
        let receipts: u64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM channel_event_receipts
                 WHERE event_id = 'event_unknown_01'",
                [],
                |row| row.get(0),
            )
            .expect("receipt count should query");
        assert_eq!(receipts, 0);
    }
}
