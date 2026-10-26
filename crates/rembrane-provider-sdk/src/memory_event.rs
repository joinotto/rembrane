use std::fmt;

use rembrane_domain::EventId;

use crate::{
    MemoryProviderContextSelector, MemoryProviderIdempotencyKey, MemoryProviderLimits,
    ProviderError,
};

pub const MAX_EVENT_TYPE_BYTES: usize = 100;
pub const MAX_EVENT_DATA_BYTES: usize = 262_144;
pub const MAX_EVENT_SOURCE_REFERENCE_BYTES: usize = 2_048;

#[derive(Clone, Eq, PartialEq)]
pub struct MemoryProviderEvent {
    event_type: String,
    selector: MemoryProviderContextSelector,
    data: String,
    source_reference: Option<String>,
    observed_at_epoch_seconds: u64,
}

impl fmt::Debug for MemoryProviderEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryProviderEvent")
            .field("event_type_bytes", &self.event_type.len())
            .field("selector", &self.selector)
            .field("data_bytes", &self.data.len())
            .field("source_reference_present", &self.source_reference.is_some())
            .field(
                "source_reference_bytes",
                &self.source_reference.as_deref().map_or(0, str::len),
            )
            .field("observed_at_epoch_seconds", &"<redacted>")
            .finish()
    }
}

impl MemoryProviderEvent {
    /// Creates one portable observation for canonical ingestion.
    ///
    /// Event data is an opaque, bounded protocol representation. It cannot
    /// contain actor, workspace, subject, or client authority; those values
    /// must be derived and enforced by the receiving server.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for malformed event types,
    /// invalid data or source references, or a zero/future observation time.
    pub fn new(
        event_type: impl Into<String>,
        selector: MemoryProviderContextSelector,
        data: impl Into<String>,
        source_reference: Option<String>,
        observed_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> Result<Self, ProviderError> {
        let event_type = event_type.into();
        if event_type.is_empty()
            || event_type.len() > MAX_EVENT_TYPE_BYTES
            || !event_type.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory event type must be a bounded portable identifier".to_owned(),
            ));
        }
        let data = data.into();
        if data.trim().is_empty() || data.len() > MAX_EVENT_DATA_BYTES || data.contains('\0') {
            return Err(ProviderError::InvalidConfiguration(
                "memory event data must be non-empty, bounded, and contain no null characters"
                    .to_owned(),
            ));
        }
        if source_reference.as_ref().is_some_and(|reference| {
            reference.is_empty()
                || reference.len() > MAX_EVENT_SOURCE_REFERENCE_BYTES
                || reference.contains('\0')
                || reference.chars().any(char::is_control)
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "memory event source reference is empty, oversized, or contains control characters"
                    .to_owned(),
            ));
        }
        if observed_at_epoch_seconds == 0 || observed_at_epoch_seconds > now_epoch_seconds {
            return Err(ProviderError::InvalidConfiguration(
                "memory event observation time must be positive and not in the future".to_owned(),
            ));
        }
        Ok(Self {
            event_type,
            selector,
            data,
            source_reference,
            observed_at_epoch_seconds,
        })
    }

    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub const fn selector(&self) -> &MemoryProviderContextSelector {
        &self.selector
    }

    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }

    #[must_use]
    pub fn source_reference(&self) -> Option<&str> {
        self.source_reference.as_deref()
    }

    #[must_use]
    pub const fn observed_at_epoch_seconds(&self) -> u64 {
        self.observed_at_epoch_seconds
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordEventPayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    events: Vec<MemoryProviderEvent>,
}

impl fmt::Debug for RecordEventPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordEventPayload")
            .field("idempotency_key", &"<redacted>")
            .field("event_count", &self.events.len())
            .field(
                "data_bytes",
                &self
                    .events
                    .iter()
                    .map(|event| event.data.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}

impl RecordEventPayload {
    /// Creates an idempotent event batch constrained by provider negotiation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an empty batch or when the
    /// batch exceeds the provider-advertised event item limit.
    pub fn new(
        idempotency_key: MemoryProviderIdempotencyKey,
        events: Vec<MemoryProviderEvent>,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        if events.is_empty() || events.len() > provider_limits.maximum_event_batch_items {
            return Err(ProviderError::InvalidConfiguration(
                "memory event batch must be non-empty and within the negotiated item limit"
                    .to_owned(),
            ));
        }
        Ok(Self {
            idempotency_key,
            events,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub fn events(&self) -> &[MemoryProviderEvent] {
        &self.events
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MemoryProviderRecordedEvent {
    event_id: EventId,
    sequence: u64,
}

impl fmt::Debug for MemoryProviderRecordedEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryProviderRecordedEvent")
            .field("event_id", &"<redacted>")
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl MemoryProviderRecordedEvent {
    /// Identifies one accepted event and its canonical workspace sequence.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe event ID or zero
    /// sequence.
    pub fn new(event_id: EventId, sequence: u64) -> Result<Self, ProviderError> {
        validate_identifier("recorded event id", event_id.as_str())?;
        if sequence == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "recorded event sequence must be greater than zero".to_owned(),
            ));
        }
        Ok(Self { event_id, sequence })
    }

    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordEventResult {
    events: Vec<MemoryProviderRecordedEvent>,
}

impl fmt::Debug for RecordEventResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordEventResult")
            .field("event_count", &self.events.len())
            .finish()
    }
}

impl RecordEventResult {
    /// Creates an ordered result corresponding exactly to the submitted batch.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an empty result, a result
    /// exceeding the negotiated limit, duplicate IDs, or non-increasing
    /// canonical sequences.
    pub fn new(
        events: Vec<MemoryProviderRecordedEvent>,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        if events.is_empty() || events.len() > provider_limits.maximum_event_batch_items {
            return Err(ProviderError::InvalidConfiguration(
                "recorded event result must be non-empty and within the negotiated item limit"
                    .to_owned(),
            ));
        }
        if events.iter().enumerate().any(|(index, event)| {
            events[..index]
                .iter()
                .any(|previous| previous.event_id == event.event_id)
                || index > 0 && events[index - 1].sequence >= event.sequence
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "recorded event IDs must be unique and sequences strictly increasing".to_owned(),
            ));
        }
        Ok(Self { events })
    }

    #[must_use]
    pub fn events(&self) -> &[MemoryProviderRecordedEvent] {
        &self.events
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must contain 1 to 255 safe ASCII characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{EntityId, EventId};

    use super::{
        MemoryProviderEvent, MemoryProviderRecordedEvent, RecordEventPayload, RecordEventResult,
    };
    use crate::{
        MemoryProviderContextSelector, MemoryProviderIdempotencyKey, MemoryProviderLimits,
    };

    fn limits(maximum_event_batch_items: usize) -> MemoryProviderLimits {
        MemoryProviderLimits {
            maximum_context_items: 10,
            maximum_context_bytes: 10_000,
            maximum_event_batch_items,
            maximum_sync_batch_items: 10,
        }
    }

    fn event(event_type: &str, observed_at: u64) -> MemoryProviderEvent {
        MemoryProviderEvent::new(
            event_type,
            MemoryProviderContextSelector::entity(EntityId::new("project_01"))
                .expect("selector should be valid"),
            r#"{"summary":"implemented authenticated endpoint"}"#,
            Some("git:81e0ac9".to_owned()),
            observed_at,
            1_000,
        )
        .expect("event should be valid")
    }

    #[test]
    fn records_an_idempotent_bounded_event_batch() {
        let payload = RecordEventPayload::new(
            MemoryProviderIdempotencyKey::new("events_0123456789abcdef")
                .expect("idempotency key should be valid"),
            vec![event("development.work-trace", 999)],
            limits(2),
        )
        .expect("event payload should be valid");
        assert_eq!(payload.events()[0].event_type(), "development.work-trace");
        assert_eq!(payload.events()[0].selector().scope().specificity(), 2);

        let result = RecordEventResult::new(
            vec![
                MemoryProviderRecordedEvent::new(EventId::new("event_01"), 7)
                    .expect("event result should be valid"),
                MemoryProviderRecordedEvent::new(EventId::new("event_02"), 8)
                    .expect("event result should be valid"),
            ],
            limits(2),
        )
        .expect("result should be valid");
        assert_eq!(result.events()[1].sequence(), 8);
    }

    #[test]
    fn rejects_invalid_events_and_batches_outside_negotiated_limits() {
        assert!(
            MemoryProviderEvent::new(
                "Invalid Type",
                MemoryProviderContextSelector::global(),
                "data",
                None,
                999,
                1_000,
            )
            .is_err()
        );
        assert!(
            MemoryProviderEvent::new(
                "work.trace",
                MemoryProviderContextSelector::global(),
                "data",
                Some("\n".to_owned()),
                999,
                1_000,
            )
            .is_err()
        );
        assert!(
            MemoryProviderEvent::new(
                "work.trace",
                MemoryProviderContextSelector::global(),
                "data",
                None,
                1_001,
                1_000,
            )
            .is_err()
        );
        assert!(
            RecordEventPayload::new(
                MemoryProviderIdempotencyKey::new("events_0123456789abcdef")
                    .expect("idempotency key should be valid"),
                vec![event("work.trace", 999), event("work.trace", 999)],
                limits(1),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_or_ambiguous_recorded_event_results() {
        assert!(MemoryProviderRecordedEvent::new(EventId::new(""), 1).is_err());
        assert!(MemoryProviderRecordedEvent::new(EventId::new("event_01"), 0).is_err());
        let recorded = |id, sequence| {
            MemoryProviderRecordedEvent::new(EventId::new(id), sequence)
                .expect("event result should be valid")
        };
        assert!(
            RecordEventResult::new(
                vec![recorded("event_01", 8), recorded("event_02", 7)],
                limits(2),
            )
            .is_err()
        );
        assert!(
            RecordEventResult::new(
                vec![recorded("event_01", 7), recorded("event_01", 8)],
                limits(2),
            )
            .is_err()
        );
    }

    #[test]
    fn event_diagnostics_redact_work_trace_provenance_time_and_identities() {
        let event = MemoryProviderEvent::new(
            "private.work-trace",
            MemoryProviderContextSelector::entity(EntityId::new("private_entity"))
                .expect("selector should be valid"),
            r#"{"summary":"private implementation detail"}"#,
            Some("private_source_reference".to_owned()),
            1_900_000_001,
            1_900_000_002,
        )
        .expect("event should be valid");
        let payload = RecordEventPayload::new(
            MemoryProviderIdempotencyKey::new("private_event_batch_key")
                .expect("idempotency key should be valid"),
            vec![event.clone()],
            limits(2),
        )
        .expect("payload should be valid");
        let recorded = MemoryProviderRecordedEvent::new(EventId::new("private_event"), 9)
            .expect("recorded event should be valid");
        let result = RecordEventResult::new(vec![recorded.clone()], limits(2))
            .expect("result should be valid");

        let diagnostic = format!("{event:?} {payload:?} {recorded:?} {result:?}");

        for private_value in [
            "private.work-trace",
            "private_entity",
            "private implementation detail",
            "private_source_reference",
            "1900000001",
            "private_event_batch_key",
            "private_event",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("event_type_bytes: 18"));
        assert!(diagnostic.contains("data_bytes: 43"));
        assert!(diagnostic.contains("source_reference_present: true"));
        assert!(diagnostic.contains("source_reference_bytes: 24"));
        assert!(diagnostic.contains("event_count: 1"));
        assert!(diagnostic.contains("sequence: 9"));
    }
}
