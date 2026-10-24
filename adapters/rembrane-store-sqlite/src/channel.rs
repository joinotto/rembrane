use rembrane_application::{
    ApplicationError, ChannelInboxRepository, ChannelIngressRepository, ChannelReplayRepository,
    ChannelSenderBindingRepository, DurableChannelIngressRepository, MAX_CHANNEL_INBOX_PAGE,
};
use rembrane_contracts::{ChannelKind, ChannelSenderBinding, VerifiedChannelMessage};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
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

impl<C: RecordCipher> DurableChannelIngressRepository for SqliteStore<C> {
    fn accept_bound_channel_event_to_inbox(
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
        let context = channel_encryption_context(&message)?;
        let encrypted = self
            .cipher
            .seal(&context, message.text().as_bytes())
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
        insert_encrypted_channel_inbox(&transaction, &message, &encrypted)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(message)
    }
}

impl<C: RecordCipher> ChannelInboxRepository for SqliteStore<C> {
    fn claim_channel_messages(
        &mut self,
        workspace_id: &WorkspaceId,
        now_epoch_seconds: u64,
        lease_until_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<VerifiedChannelMessage>, ApplicationError> {
        if now_epoch_seconds == 0 || lease_until_epoch_seconds <= now_epoch_seconds {
            return Err(ApplicationError::Validation(
                "channel inbox lease must end after the current time".to_owned(),
            ));
        }
        if !(1..=MAX_CHANNEL_INBOX_PAGE).contains(&limit) {
            return Err(ApplicationError::Validation(
                "channel inbox page limit is invalid".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT
                    inbox.channel, inbox.event_id, inbox.principal_id,
                    inbox.client_id, inbox.received_at_epoch_seconds,
                    inbox.text_ciphertext, inbox.encryption_key_id,
                    inbox.encryption_algorithm, inbox.encryption_nonce
                 FROM channel_inbox AS inbox
                 JOIN memberships AS membership
                   ON membership.workspace_id = inbox.workspace_id
                  AND membership.principal_id = inbox.principal_id
                  AND membership.status = 'active'
                 WHERE inbox.workspace_id = ?1
                   AND (
                       (inbox.status = 'pending'
                        AND inbox.available_at_epoch_seconds <= ?2)
                       OR (inbox.status = 'processing'
                           AND inbox.lease_until_epoch_seconds <= ?2)
                   )
                 ORDER BY inbox.received_at_epoch_seconds, inbox.channel, inbox.event_id
                 LIMIT ?3",
                )
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            statement
                .query_map(
                    params![
                        workspace_id.as_str(),
                        now_epoch_seconds,
                        i64::try_from(limit).map_err(|_| {
                            ApplicationError::Validation(
                                "channel inbox page limit exceeds SQLite range".to_owned(),
                            )
                        })?
                    ],
                    |row| {
                        Ok(ChannelInboxRow {
                            channel: row.get(0)?,
                            event_id: row.get(1)?,
                            principal_id: row.get(2)?,
                            client_id: row.get(3)?,
                            received_at_epoch_seconds: row.get(4)?,
                            ciphertext: row.get(5)?,
                            key_id: row.get(6)?,
                            algorithm: row.get(7)?,
                            nonce: row.get(8)?,
                        })
                    },
                )
                .map_err(|_| ApplicationError::StorageUnavailable)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ApplicationError::StorageUnavailable)?
        };
        for row in &rows {
            let changed = transaction
                .execute(
                    "UPDATE channel_inbox
                     SET status = 'processing', lease_until_epoch_seconds = ?4
                     WHERE workspace_id = ?1
                       AND channel = ?2
                       AND event_id = ?3
                       AND (
                           (status = 'pending' AND available_at_epoch_seconds <= ?5)
                           OR (status = 'processing' AND lease_until_epoch_seconds <= ?5)
                       )",
                    params![
                        workspace_id.as_str(),
                        row.channel,
                        row.event_id,
                        lease_until_epoch_seconds,
                        now_epoch_seconds
                    ],
                )
                .map_err(map_write_error)?;
            if changed != 1 {
                return Err(ApplicationError::StorageUnavailable);
            }
        }
        transaction.commit().map_err(map_write_error)?;
        rows.into_iter()
            .map(|row| decode_channel_inbox_row(&self.cipher, workspace_id, row))
            .collect()
    }

    fn fail_channel_message(
        &mut self,
        workspace_id: &WorkspaceId,
        channel: ChannelKind,
        event_id: &str,
        retry_at_epoch_seconds: u64,
        maximum_attempts: u32,
    ) -> Result<bool, ApplicationError> {
        if retry_at_epoch_seconds == 0 || maximum_attempts == 0 {
            return Err(ApplicationError::Validation(
                "channel retry limits must be positive".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE channel_inbox
                 SET attempts = attempts + 1,
                     status = CASE
                         WHEN attempts + 1 >= ?4 THEN 'quarantined'
                         ELSE 'pending'
                     END,
                     available_at_epoch_seconds = ?5,
                     lease_until_epoch_seconds = NULL
                 WHERE workspace_id = ?1
                   AND channel = ?2
                   AND event_id = ?3
                   AND status = 'processing'",
                params![
                    workspace_id.as_str(),
                    encode_channel(channel),
                    event_id,
                    maximum_attempts,
                    retry_at_epoch_seconds
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::NotFound);
        }
        let quarantined = transaction
            .query_row(
                "SELECT status = 'quarantined'
                 FROM channel_inbox
                 WHERE workspace_id = ?1 AND channel = ?2 AND event_id = ?3",
                params![workspace_id.as_str(), encode_channel(channel), event_id],
                |row| row.get(0),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(quarantined)
    }

    fn complete_channel_message(
        &mut self,
        workspace_id: &WorkspaceId,
        channel: ChannelKind,
        event_id: &str,
    ) -> Result<(), ApplicationError> {
        let changed = self
            .connection
            .execute(
                "UPDATE channel_inbox
                 SET status = 'delivered',
                     delivered_at = CURRENT_TIMESTAMP,
                     lease_until_epoch_seconds = NULL
                 WHERE workspace_id = ?1
                   AND channel = ?2
                   AND event_id = ?3
                   AND status = 'processing'",
                params![workspace_id.as_str(), encode_channel(channel), event_id],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::NotFound);
        }
        Ok(())
    }
}

struct ChannelInboxRow {
    channel: String,
    event_id: String,
    principal_id: String,
    client_id: String,
    received_at_epoch_seconds: u64,
    ciphertext: Vec<u8>,
    key_id: String,
    algorithm: String,
    nonce: Vec<u8>,
}

fn decode_channel_inbox_row<C: RecordCipher>(
    cipher: &C,
    workspace_id: &WorkspaceId,
    row: ChannelInboxRow,
) -> Result<VerifiedChannelMessage, ApplicationError> {
    let channel = decode_channel(&row.channel)?;
    let message_without_text = VerifiedChannelMessage::from_authenticated_transport(
        channel,
        &row.event_id,
        workspace_id.clone(),
        PrincipalId::new(&row.principal_id),
        ClientId::new(&row.client_id),
        "encrypted",
        row.received_at_epoch_seconds,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = channel_encryption_context(&message_without_text)?;
    let encrypted = EncryptedPayload::new(row.ciphertext, row.key_id, row.algorithm, row.nonce)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let plaintext = cipher
        .open(&context, &encrypted)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let text = String::from_utf8(plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
    VerifiedChannelMessage::from_authenticated_transport(
        channel,
        row.event_id,
        workspace_id.clone(),
        PrincipalId::new(row.principal_id),
        ClientId::new(row.client_id),
        text,
        row.received_at_epoch_seconds,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)
}

fn channel_encryption_context(
    message: &VerifiedChannelMessage,
) -> Result<EncryptionContext, ApplicationError> {
    EncryptionContext::new(
        message.workspace_id().clone(),
        format!("{}:{}", message.channel().label(), message.event_id()),
        1,
        PayloadPurpose::ChannelMessage,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)
}

fn insert_encrypted_channel_inbox(
    connection: &rusqlite::Connection,
    message: &VerifiedChannelMessage,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError> {
    connection
        .execute(
            "INSERT INTO channel_inbox (
                channel, event_id, workspace_id, principal_id, client_id,
                received_at_epoch_seconds, text_ciphertext,
                encryption_key_id, encryption_algorithm, encryption_nonce,
                available_at_epoch_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?6)",
            params![
                encode_channel(message.channel()),
                message.event_id(),
                message.workspace_id().as_str(),
                message.principal_id().as_str(),
                message.client_id().as_str(),
                message.received_at_epoch_seconds(),
                encrypted.ciphertext(),
                encrypted.key_id(),
                encrypted.algorithm(),
                encrypted.nonce(),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

const fn encode_channel(channel: ChannelKind) -> &'static str {
    channel.label()
}

fn decode_channel(channel: &str) -> Result<ChannelKind, ApplicationError> {
    match channel {
        "whatsapp-business" => Ok(ChannelKind::WhatsAppBusiness),
        "imessage-extension" => Ok(ChannelKind::IMessageExtension),
        "mobile-share" => Ok(ChannelKind::MobileShare),
        _ => Err(ApplicationError::StorageUnavailable),
    }
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
        ChannelInboxRepository, ChannelIngressRepository, ChannelReplayRepository,
        ChannelSenderBindingRepository, CreateChannelBindingCommand,
        DurableChannelIngressRepository, MembershipRepository, RevokeChannelBindingCommand,
        WorkspaceRepository,
    };
    use rembrane_contracts::{ChannelKind, ChannelSenderBinding, VerifiedChannelMessage};
    use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
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
    fn durable_admission_encrypts_recovers_and_completes_tenant_inbox() {
        let mut store = store();
        store
            .insert_channel_sender_binding(
                ChannelSenderBinding::new(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-inbox",
                    "hmac-sender-inbox",
                    WorkspaceId::new("workspace_01"),
                    PrincipalId::new("principal_01"),
                    ClientId::new("client_whatsapp_inbox"),
                )
                .expect("binding should validate"),
            )
            .expect("binding should persist");
        let cipher =
            RustCryptoRecordCipher::new("channel-test-key", [23; 32]).expect("key should validate");
        let mut store = store.with_cipher(cipher);
        let admitted = store
            .accept_bound_channel_event_to_inbox(
                ChannelKind::WhatsAppBusiness,
                "hmac-account-inbox",
                "hmac-sender-inbox",
                "event-inbox-01",
                "Continue my private trip search",
                1_000,
                1_000,
                100,
                10,
            )
            .expect("bound event should durably enqueue");
        assert_eq!(admitted.workspace_id().as_str(), "workspace_01");
        let stored_text: Vec<u8> = store
            .connection
            .query_row(
                "SELECT text_ciphertext FROM channel_inbox
                 WHERE channel='whatsapp-business' AND event_id='event-inbox-01'",
                [],
                |row| row.get(0),
            )
            .expect("ciphertext should persist");
        assert_ne!(stored_text, admitted.text().as_bytes());
        assert!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_02"), 1_000, 1_060, 10)
                .expect("other tenant query should succeed")
                .is_empty()
        );
        assert_eq!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_000, 1_060, 10)
                .expect("inbox should decrypt"),
            vec![admitted.clone()]
        );
        store
            .complete_channel_message(
                &WorkspaceId::new("workspace_01"),
                ChannelKind::WhatsAppBusiness,
                admitted.event_id(),
            )
            .expect("delivery should complete");
        assert!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_000, 1_060, 10)
                .expect("completed inbox query should succeed")
                .is_empty()
        );
        assert_eq!(
            store
                .complete_channel_message(
                    &WorkspaceId::new("workspace_01"),
                    ChannelKind::WhatsAppBusiness,
                    admitted.event_id(),
                )
                .expect_err("completion must be monotonic"),
            ApplicationError::NotFound
        );
    }

    #[test]
    fn failed_channel_delivery_is_delayed_then_quarantined() {
        let mut store = store();
        store
            .insert_channel_sender_binding(
                ChannelSenderBinding::new(
                    ChannelKind::WhatsAppBusiness,
                    "hmac-account-retry",
                    "hmac-sender-retry",
                    WorkspaceId::new("workspace_01"),
                    PrincipalId::new("principal_01"),
                    ClientId::new("client_whatsapp_retry"),
                )
                .expect("binding should validate"),
            )
            .expect("binding should persist");
        let cipher = RustCryptoRecordCipher::new("channel-retry-key", [29; 32]).expect("valid key");
        let mut store = store.with_cipher(cipher);
        let admitted = store
            .accept_bound_channel_event_to_inbox(
                ChannelKind::WhatsAppBusiness,
                "hmac-account-retry",
                "hmac-sender-retry",
                "event-retry-01",
                "retry me",
                1_000,
                1_000,
                100,
                10,
            )
            .expect("event should enqueue");
        assert_eq!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_000, 1_060, 10)
                .expect("first worker should claim"),
            vec![admitted.clone()]
        );
        assert!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_001, 1_061, 10)
                .expect("second worker query should succeed")
                .is_empty()
        );

        assert!(
            !store
                .fail_channel_message(
                    &WorkspaceId::new("workspace_01"),
                    ChannelKind::WhatsAppBusiness,
                    admitted.event_id(),
                    1_030,
                    2,
                )
                .expect("first failure should schedule retry")
        );
        assert!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_029, 1_089, 10)
                .expect("early query should succeed")
                .is_empty()
        );
        assert_eq!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 1_030, 1_090, 10)
                .expect("retry should become available"),
            vec![admitted.clone()]
        );
        assert!(
            store
                .fail_channel_message(
                    &WorkspaceId::new("workspace_01"),
                    ChannelKind::WhatsAppBusiness,
                    admitted.event_id(),
                    1_060,
                    2,
                )
                .expect("second failure should quarantine")
        );
        assert!(
            store
                .claim_channel_messages(&WorkspaceId::new("workspace_01"), 2_000, 2_060, 10)
                .expect("quarantined query should succeed")
                .is_empty()
        );
        assert_eq!(
            store
                .fail_channel_message(
                    &WorkspaceId::new("workspace_01"),
                    ChannelKind::WhatsAppBusiness,
                    admitted.event_id(),
                    2_030,
                    2,
                )
                .expect_err("quarantine must be terminal"),
            ApplicationError::NotFound
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
