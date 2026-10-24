use std::error::Error;
use std::fmt::{self, Display};

use crate::{BookingResearchId, EntityId, EvidenceReference, PrincipalId, WorkspaceId};

pub const MAX_BOOKING_RESEARCH_FIELD_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookingResearchKind {
    Flight,
    Lodging,
    GroundTransport,
    Activity,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResearchFreshness {
    Fresh,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookingResearch {
    id: BookingResearchId,
    workspace_id: WorkspaceId,
    trip_id: EntityId,
    observed_by: PrincipalId,
    kind: BookingResearchKind,
    provider: String,
    summary: String,
    source_reference: String,
    evidence: EvidenceReference,
    observed_at: String,
    expires_at: String,
    version: u64,
}

impl BookingResearch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: BookingResearchId,
        workspace_id: WorkspaceId,
        trip_id: EntityId,
        observed_by: PrincipalId,
        kind: BookingResearchKind,
        provider: impl Into<String>,
        summary: impl Into<String>,
        source_reference: impl Into<String>,
        evidence: EvidenceReference,
        observed_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Result<Self, BookingResearchError> {
        Self::restore(
            id,
            workspace_id,
            trip_id,
            observed_by,
            kind,
            provider,
            summary,
            source_reference,
            evidence,
            observed_at,
            expires_at,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: BookingResearchId,
        workspace_id: WorkspaceId,
        trip_id: EntityId,
        observed_by: PrincipalId,
        kind: BookingResearchKind,
        provider: impl Into<String>,
        summary: impl Into<String>,
        source_reference: impl Into<String>,
        evidence: EvidenceReference,
        observed_at: impl Into<String>,
        expires_at: impl Into<String>,
        version: u64,
    ) -> Result<Self, BookingResearchError> {
        let provider = provider.into();
        let summary = summary.into();
        let source_reference = source_reference.into();
        let observed_at = observed_at.into();
        let expires_at = expires_at.into();
        validate_field(&provider)?;
        validate_field(&summary)?;
        validate_field(&source_reference)?;
        if !valid_utc_timestamp(&observed_at) || !valid_utc_timestamp(&expires_at) {
            return Err(BookingResearchError::InvalidTimestamp);
        }
        if expires_at <= observed_at {
            return Err(BookingResearchError::InvalidExpiry);
        }
        if version == 0 {
            return Err(BookingResearchError::InvalidVersion);
        }
        Ok(Self {
            id,
            workspace_id,
            trip_id,
            observed_by,
            kind,
            provider,
            summary,
            source_reference,
            evidence,
            observed_at,
            expires_at,
            version,
        })
    }

    pub fn freshness_at(&self, timestamp: &str) -> Result<ResearchFreshness, BookingResearchError> {
        if !valid_utc_timestamp(timestamp) {
            return Err(BookingResearchError::InvalidTimestamp);
        }
        if timestamp < self.expires_at.as_str() {
            Ok(ResearchFreshness::Fresh)
        } else {
            Ok(ResearchFreshness::Expired)
        }
    }

    #[must_use]
    pub const fn id(&self) -> &BookingResearchId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn trip_id(&self) -> &EntityId {
        &self.trip_id
    }

    #[must_use]
    pub const fn observed_by(&self) -> &PrincipalId {
        &self.observed_by
    }

    #[must_use]
    pub const fn kind(&self) -> BookingResearchKind {
        self.kind
    }

    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn source_reference(&self) -> &str {
        &self.source_reference
    }

    #[must_use]
    pub const fn evidence(&self) -> &EvidenceReference {
        &self.evidence
    }

    #[must_use]
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }

    #[must_use]
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookingResearchError {
    EmptyField,
    FieldTooLarge,
    InvalidTimestamp,
    InvalidExpiry,
    InvalidVersion,
}

impl Display for BookingResearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField => formatter.write_str("booking research field is empty"),
            Self::FieldTooLarge => formatter.write_str("booking research field is too large"),
            Self::InvalidTimestamp => formatter.write_str("timestamp must be canonical UTC"),
            Self::InvalidExpiry => formatter.write_str("expiry must follow observation time"),
            Self::InvalidVersion => formatter.write_str("booking research version is invalid"),
        }
    }
}

impl Error for BookingResearchError {}

fn validate_field(value: &str) -> Result<(), BookingResearchError> {
    if value.trim().is_empty() {
        return Err(BookingResearchError::EmptyField);
    }
    if value.len() > MAX_BOOKING_RESEARCH_FIELD_BYTES {
        return Err(BookingResearchError::FieldTooLarge);
    }
    Ok(())
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let parse = |start: usize, end: usize| value[start..end].parse::<u32>().unwrap_or(u32::MAX);
    let year = parse(0, 4);
    let month = parse(5, 7);
    let day = parse(8, 10);
    let hour = parse(11, 13);
    let minute = parse(14, 16);
    let second = parse(17, 19);
    year > 0
        && (1..=12).contains(&month)
        && day > 0
        && day <= days_in_month(year, month)
        && hour < 24
        && minute < 60
        && second < 60
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BookingResearchId, EntityId, EvidenceId, EvidenceReference, EvidenceSource, PrincipalId,
        WorkspaceId,
    };

    use super::{BookingResearch, BookingResearchError, BookingResearchKind, ResearchFreshness};

    fn research(
        observed_at: &str,
        expires_at: &str,
    ) -> Result<BookingResearch, BookingResearchError> {
        BookingResearch::new(
            BookingResearchId::new("research_01"),
            WorkspaceId::new("workspace_01"),
            EntityId::new("trip_01"),
            PrincipalId::new("principal_01"),
            BookingResearchKind::Flight,
            "airline-search",
            "Nonstop morning option",
            "opaque-result-01",
            EvidenceReference::new(EvidenceId::new("evidence_01"), EvidenceSource::ToolResult),
            observed_at,
            expires_at,
        )
    }

    #[test]
    fn reports_freshness_at_the_expiry_boundary() {
        let research = research("2026-10-24T10:00:00Z", "2026-10-24T10:30:00Z")
            .expect("research should be valid");

        assert_eq!(
            research.freshness_at("2026-10-24T10:29:59Z"),
            Ok(ResearchFreshness::Fresh)
        );
        assert_eq!(
            research.freshness_at("2026-10-24T10:30:00Z"),
            Ok(ResearchFreshness::Expired)
        );
    }

    #[test]
    fn rejects_invalid_calendar_time_and_nonfuture_expiry() {
        assert_eq!(
            research("2026-02-29T10:00:00Z", "2026-03-01T10:00:00Z"),
            Err(BookingResearchError::InvalidTimestamp)
        );
        assert_eq!(
            research("2026-10-24T10:00:00Z", "2026-10-24T10:00:00Z"),
            Err(BookingResearchError::InvalidExpiry)
        );
    }

    #[test]
    fn restored_records_require_a_positive_version() {
        let original = research("2026-10-24T10:00:00Z", "2026-10-24T10:30:00Z")
            .expect("research should be valid");
        assert_eq!(
            BookingResearch::restore(
                original.id().clone(),
                original.workspace_id().clone(),
                original.trip_id().clone(),
                original.observed_by().clone(),
                original.kind(),
                original.provider(),
                original.summary(),
                original.source_reference(),
                original.evidence().clone(),
                original.observed_at(),
                original.expires_at(),
                0,
            ),
            Err(BookingResearchError::InvalidVersion)
        );
    }
}
