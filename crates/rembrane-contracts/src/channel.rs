use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

pub const MAX_CHANNEL_EVENT_ID_BYTES: usize = 256;
pub const MAX_CHANNEL_TEXT_BYTES: usize = 16_384;
pub const MAX_CHANNEL_LOOKUP_KEY_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChannelKind {
    WhatsAppBusiness,
    IMessageExtension,
    MobileShare,
}

impl ChannelKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WhatsAppBusiness => "whatsapp-business",
            Self::IMessageExtension => "imessage-extension",
            Self::MobileShare => "mobile-share",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedChannelMessage {
    channel: ChannelKind,
    event_id: String,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    client_id: ClientId,
    text: String,
    received_at_epoch_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelMessageError {
    InvalidEventId,
    InvalidText,
    InvalidTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelSenderBinding {
    channel: ChannelKind,
    account_lookup_key: String,
    sender_lookup_key: String,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    client_id: ClientId,
}

impl VerifiedChannelMessage {
    /// Constructs an inbound event only after a transport adapter has
    /// authenticated the platform signature and resolved the external sender
    /// through a deployment-owned account binding.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identifiers, empty or oversized text, and zero time.
    pub fn from_authenticated_transport(
        channel: ChannelKind,
        event_id: impl Into<String>,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        client_id: ClientId,
        text: impl Into<String>,
        received_at_epoch_seconds: u64,
    ) -> Result<Self, ChannelMessageError> {
        let event_id = event_id.into();
        let text = text.into();
        if event_id.is_empty()
            || event_id.len() > MAX_CHANNEL_EVENT_ID_BYTES
            || event_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ChannelMessageError::InvalidEventId);
        }
        if text.trim().is_empty() || text.len() > MAX_CHANNEL_TEXT_BYTES {
            return Err(ChannelMessageError::InvalidText);
        }
        if received_at_epoch_seconds == 0 {
            return Err(ChannelMessageError::InvalidTime);
        }
        Ok(Self {
            channel,
            event_id,
            workspace_id,
            principal_id,
            client_id,
            text,
            received_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn channel(&self) -> ChannelKind {
        self.channel
    }

    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn received_at_epoch_seconds(&self) -> u64 {
        self.received_at_epoch_seconds
    }
}

impl ChannelSenderBinding {
    /// Creates a deployment-owned binding from keyed pseudonymous lookup
    /// identifiers. Raw platform account identifiers must not be supplied.
    pub fn new(
        channel: ChannelKind,
        account_lookup_key: impl Into<String>,
        sender_lookup_key: impl Into<String>,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        client_id: ClientId,
    ) -> Result<Self, ChannelMessageError> {
        let account_lookup_key = account_lookup_key.into();
        let sender_lookup_key = sender_lookup_key.into();
        if !valid_lookup_key(&account_lookup_key) || !valid_lookup_key(&sender_lookup_key) {
            return Err(ChannelMessageError::InvalidEventId);
        }
        Ok(Self {
            channel,
            account_lookup_key,
            sender_lookup_key,
            workspace_id,
            principal_id,
            client_id,
        })
    }

    #[must_use]
    pub const fn channel(&self) -> ChannelKind {
        self.channel
    }

    #[must_use]
    pub fn account_lookup_key(&self) -> &str {
        &self.account_lookup_key
    }

    #[must_use]
    pub fn sender_lookup_key(&self) -> &str {
        &self.sender_lookup_key
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }
}

fn valid_lookup_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CHANNEL_LOOKUP_KEY_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

impl Display for ChannelMessageError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEventId => "channel event identifier is invalid",
            Self::InvalidText => "channel message text is invalid",
            Self::InvalidTime => "channel receipt time is invalid",
        })
    }
}

impl Error for ChannelMessageError {}

#[cfg(test)]
mod tests {
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{ChannelKind, ChannelMessageError, VerifiedChannelMessage};

    #[test]
    fn authenticated_channel_identity_is_canonical_and_bounded() {
        let message = VerifiedChannelMessage::from_authenticated_transport(
            ChannelKind::WhatsAppBusiness,
            "wamid.opaque",
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_whatsapp_01"),
            "Continue my flight research",
            1_000,
        )
        .expect("verified event should be valid");
        assert_eq!(message.workspace_id().as_str(), "workspace_01");
        assert_eq!(message.event_id(), "wamid.opaque");

        assert_eq!(
            VerifiedChannelMessage::from_authenticated_transport(
                ChannelKind::MobileShare,
                "unsafe event",
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                ClientId::new("client_01"),
                "text",
                1_000,
            )
            .expect_err("unsafe event id must fail"),
            ChannelMessageError::InvalidEventId
        );
    }
}
