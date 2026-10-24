//! Versioned, provider-independent serialization for encrypted canonical data.

mod checkpoint;
mod event;
mod trip;

use std::error::Error;
use std::fmt::{self, Display};

use rembrane_domain::{
    ActivityId, EntityId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind,
    MemoryRecord, MemoryScope, MemoryStatus, PrincipalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

pub use checkpoint::{decode_checkpoint, encode_checkpoint};
pub use event::{decode_event, encode_event};
pub use trip::{decode_trip, encode_trip};

const MEMORY_FORMAT: &str = "rembrane.memory";
const MEMORY_FORMAT_VERSION: u16 = 1;

#[derive(Debug)]
pub enum CodecError {
    InvalidDomainRecord,
    MalformedPayload,
    UnsupportedFormat,
    UnsupportedVersion,
}

impl Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomainRecord => formatter.write_str("decoded domain record is invalid"),
            Self::MalformedPayload => formatter.write_str("payload is malformed"),
            Self::UnsupportedFormat => formatter.write_str("payload format is unsupported"),
            Self::UnsupportedVersion => formatter.write_str("payload version is unsupported"),
        }
    }
}

impl Error for CodecError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryEnvelope {
    format: String,
    version: u16,
    record: MemoryDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryDto {
    id: String,
    workspace_id: String,
    subject_id: String,
    scope: ScopeDto,
    kind: MemoryKindDto,
    status: MemoryStatusDto,
    content: String,
    record_version: u64,
    evidence: Vec<EvidenceDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "kebab-case")]
enum ScopeDto {
    Global,
    Domain { name: String },
    Entity { id: String },
    Activity { id: String },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MemoryKindDto {
    Preference,
    Semantic,
    Episodic,
    Procedural,
    Observation,
    Working,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum MemoryStatusDto {
    Proposed,
    Confirmed,
    Superseded,
    Deleted,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDto {
    id: String,
    source: EvidenceSourceDto,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceSourceDto {
    UserStatement,
    AgentObservation,
    ToolResult,
    ImportedRecord,
    WorkspaceDecision,
}

pub fn encode_memory(memory: &MemoryRecord) -> Result<Vec<u8>, CodecError> {
    let envelope = MemoryEnvelope {
        format: MEMORY_FORMAT.to_owned(),
        version: MEMORY_FORMAT_VERSION,
        record: MemoryDto::from(memory),
    };

    serde_json::to_vec(&envelope).map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_memory(payload: &[u8]) -> Result<MemoryRecord, CodecError> {
    let envelope: MemoryEnvelope =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if envelope.format != MEMORY_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if envelope.version != MEMORY_FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }

    MemoryRecord::try_from(envelope.record)
}

impl From<&MemoryRecord> for MemoryDto {
    fn from(memory: &MemoryRecord) -> Self {
        Self {
            id: memory.id().as_str().to_owned(),
            workspace_id: memory.workspace_id().as_str().to_owned(),
            subject_id: memory.subject_id().as_str().to_owned(),
            scope: ScopeDto::from(memory.scope()),
            kind: MemoryKindDto::from(memory.kind()),
            status: MemoryStatusDto::from(memory.status()),
            content: memory.content().to_owned(),
            record_version: memory.version(),
            evidence: memory.evidence().iter().map(EvidenceDto::from).collect(),
        }
    }
}

impl TryFrom<MemoryDto> for MemoryRecord {
    type Error = CodecError;

    fn try_from(memory: MemoryDto) -> Result<Self, Self::Error> {
        MemoryRecord::restore(
            MemoryId::new(memory.id),
            WorkspaceId::new(memory.workspace_id),
            PrincipalId::new(memory.subject_id),
            MemoryScope::from(memory.scope),
            MemoryKind::from(memory.kind),
            MemoryStatus::from(memory.status),
            memory.content,
            memory.record_version,
            memory
                .evidence
                .into_iter()
                .map(EvidenceReference::from)
                .collect(),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&MemoryScope> for ScopeDto {
    fn from(scope: &MemoryScope) -> Self {
        match scope {
            MemoryScope::Global => Self::Global,
            MemoryScope::Domain { name } => Self::Domain { name: name.clone() },
            MemoryScope::Entity { id } => Self::Entity {
                id: id.as_str().to_owned(),
            },
            MemoryScope::Activity { id } => Self::Activity {
                id: id.as_str().to_owned(),
            },
        }
    }
}

impl From<ScopeDto> for MemoryScope {
    fn from(scope: ScopeDto) -> Self {
        match scope {
            ScopeDto::Global => Self::Global,
            ScopeDto::Domain { name } => Self::Domain { name },
            ScopeDto::Entity { id } => Self::Entity {
                id: EntityId::new(id),
            },
            ScopeDto::Activity { id } => Self::Activity {
                id: ActivityId::new(id),
            },
        }
    }
}

impl From<MemoryKind> for MemoryKindDto {
    fn from(kind: MemoryKind) -> Self {
        match kind {
            MemoryKind::Preference => Self::Preference,
            MemoryKind::Semantic => Self::Semantic,
            MemoryKind::Episodic => Self::Episodic,
            MemoryKind::Procedural => Self::Procedural,
            MemoryKind::Observation => Self::Observation,
            MemoryKind::Working => Self::Working,
        }
    }
}

impl From<MemoryKindDto> for MemoryKind {
    fn from(kind: MemoryKindDto) -> Self {
        match kind {
            MemoryKindDto::Preference => Self::Preference,
            MemoryKindDto::Semantic => Self::Semantic,
            MemoryKindDto::Episodic => Self::Episodic,
            MemoryKindDto::Procedural => Self::Procedural,
            MemoryKindDto::Observation => Self::Observation,
            MemoryKindDto::Working => Self::Working,
        }
    }
}

impl From<MemoryStatus> for MemoryStatusDto {
    fn from(status: MemoryStatus) -> Self {
        match status {
            MemoryStatus::Proposed => Self::Proposed,
            MemoryStatus::Confirmed => Self::Confirmed,
            MemoryStatus::Superseded => Self::Superseded,
            MemoryStatus::Deleted => Self::Deleted,
        }
    }
}

impl From<MemoryStatusDto> for MemoryStatus {
    fn from(status: MemoryStatusDto) -> Self {
        match status {
            MemoryStatusDto::Proposed => Self::Proposed,
            MemoryStatusDto::Confirmed => Self::Confirmed,
            MemoryStatusDto::Superseded => Self::Superseded,
            MemoryStatusDto::Deleted => Self::Deleted,
        }
    }
}

impl From<&EvidenceReference> for EvidenceDto {
    fn from(evidence: &EvidenceReference) -> Self {
        Self {
            id: evidence.id.as_str().to_owned(),
            source: EvidenceSourceDto::from(evidence.source),
        }
    }
}

impl From<EvidenceDto> for EvidenceReference {
    fn from(evidence: EvidenceDto) -> Self {
        Self::new(
            EvidenceId::new(evidence.id),
            EvidenceSource::from(evidence.source),
        )
    }
}

impl From<EvidenceSource> for EvidenceSourceDto {
    fn from(source: EvidenceSource) -> Self {
        match source {
            EvidenceSource::UserStatement => Self::UserStatement,
            EvidenceSource::AgentObservation => Self::AgentObservation,
            EvidenceSource::ToolResult => Self::ToolResult,
            EvidenceSource::ImportedRecord => Self::ImportedRecord,
            EvidenceSource::WorkspaceDecision => Self::WorkspaceDecision,
        }
    }
}

impl From<EvidenceSourceDto> for EvidenceSource {
    fn from(source: EvidenceSourceDto) -> Self {
        match source {
            EvidenceSourceDto::UserStatement => Self::UserStatement,
            EvidenceSourceDto::AgentObservation => Self::AgentObservation,
            EvidenceSourceDto::ToolResult => Self::ToolResult,
            EvidenceSourceDto::ImportedRecord => Self::ImportedRecord,
            EvidenceSourceDto::WorkspaceDecision => Self::WorkspaceDecision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CodecError, decode_memory, encode_memory};
    use rembrane_domain::{
        EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryRecord, MemoryScope,
        PrincipalId, WorkspaceId,
    };

    fn preference() -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("fixture is valid")
    }

    #[test]
    fn round_trips_confirmed_preference() {
        let original = preference();
        let encoded = encode_memory(&original).expect("encoding succeeds");
        let decoded = decode_memory(&encoded).expect("decoding succeeds");

        assert_eq!(decoded, original);
    }

    #[test]
    fn preserves_memory_v1_wire_fixture() {
        let encoded = encode_memory(&preference()).expect("encoding succeeds");
        let expected = include_str!("../fixtures/memory-v1-confirmed-preference.json")
            .trim_end()
            .as_bytes();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn rejects_unknown_format_version() {
        let encoded = encode_memory(&preference()).expect("encoding succeeds");
        let incompatible = String::from_utf8(encoded)
            .expect("JSON payload is UTF-8")
            .replace("\"version\":1", "\"version\":2");

        assert!(matches!(
            decode_memory(incompatible.as_bytes()),
            Err(CodecError::UnsupportedVersion)
        ));
    }

    #[test]
    fn rejects_unknown_fields() {
        let encoded = encode_memory(&preference()).expect("encoding succeeds");
        let incompatible = String::from_utf8(encoded)
            .expect("JSON payload is UTF-8")
            .replace("\"record\":{", "\"unexpected\":true,\"record\":{");

        assert!(matches!(
            decode_memory(incompatible.as_bytes()),
            Err(CodecError::MalformedPayload)
        ));
    }
}
