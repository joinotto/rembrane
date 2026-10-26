use rembrane_domain::{
    ActivityId, EntityId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind,
    MemoryRecord, MemoryScope, MemoryStatus, PrincipalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::CodecError;

pub const MEMORY_JSONL_FORMAT: &str = "rembrane-memory-jsonl";
pub const MEMORY_JSONL_VERSION: u32 = 1;
pub const MAX_MEMORY_JSONL_LINE_BYTES: usize = 1_048_576;
pub const MAX_MEMORY_JSONL_ARCHIVE_BYTES: usize = 67_108_864;
pub const MAX_MEMORY_JSONL_ARCHIVE_RECORDS: usize = 10_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableMemoryRecord {
    format: String,
    format_version: u32,
    workspace_id: String,
    subject_id: String,
    memory_id: String,
    version: u64,
    scope: PortableScope,
    kind: PortableMemoryKind,
    status: PortableMemoryStatus,
    content: String,
    evidence: Vec<PortableEvidence>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "kebab-case")]
enum PortableScope {
    Global,
    Domain { name: String },
    Entity { id: String },
    Activity { id: String },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PortableMemoryKind {
    Preference,
    Semantic,
    Episodic,
    Procedural,
    Observation,
    Working,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PortableMemoryStatus {
    Proposed,
    Confirmed,
    Superseded,
    Deleted,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableEvidence {
    id: String,
    source: PortableEvidenceSource,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PortableEvidenceSource {
    UserStatement,
    AgentObservation,
    ToolResult,
    ImportedRecord,
    WorkspaceDecision,
}

pub fn encode_memory_jsonl_record(memory: &MemoryRecord) -> Result<Vec<u8>, CodecError> {
    let mut encoded = serde_json::to_vec(&PortableMemoryRecord::from(memory))
        .map_err(|_| CodecError::MalformedPayload)?;
    if encoded.len() >= MAX_MEMORY_JSONL_LINE_BYTES {
        return Err(CodecError::MalformedPayload);
    }
    encoded.push(b'\n');
    Ok(encoded)
}

pub fn decode_memory_jsonl_record(payload: &[u8]) -> Result<MemoryRecord, CodecError> {
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
    if payload.is_empty() || payload.len() > MAX_MEMORY_JSONL_LINE_BYTES {
        return Err(CodecError::MalformedPayload);
    }
    let record: PortableMemoryRecord =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if record.format != MEMORY_JSONL_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if record.format_version != MEMORY_JSONL_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    MemoryRecord::try_from(record)
}

pub fn decode_memory_jsonl_archive(payload: &[u8]) -> Result<Vec<MemoryRecord>, CodecError> {
    decode_memory_jsonl_archive_with_limits(
        payload,
        MAX_MEMORY_JSONL_ARCHIVE_RECORDS,
        MAX_MEMORY_JSONL_ARCHIVE_BYTES,
    )
}

fn decode_memory_jsonl_archive_with_limits(
    payload: &[u8],
    maximum_records: usize,
    maximum_bytes: usize,
) -> Result<Vec<MemoryRecord>, CodecError> {
    if payload.len() > maximum_bytes {
        return Err(CodecError::MalformedPayload);
    }
    let mut records = Vec::new();
    let mut identities = HashSet::new();
    let mut source_tenant: Option<(WorkspaceId, PrincipalId)> = None;
    for line in payload.split_inclusive(|byte| *byte == b'\n') {
        if line == b"\n" || line == b"\r\n" {
            return Err(CodecError::MalformedPayload);
        }
        if records.len() == maximum_records {
            return Err(CodecError::MalformedPayload);
        }
        let record = decode_memory_jsonl_record(line)?;
        let tenant = (record.workspace_id().clone(), record.subject_id().clone());
        if source_tenant
            .as_ref()
            .is_some_and(|source| source != &tenant)
        {
            return Err(CodecError::InvalidDomainRecord);
        }
        source_tenant.get_or_insert(tenant);
        if !identities.insert((
            record.workspace_id().clone(),
            record.id().clone(),
            record.version(),
        )) {
            return Err(CodecError::InvalidDomainRecord);
        }
        records.push(record);
    }
    Ok(records)
}

impl From<&MemoryRecord> for PortableMemoryRecord {
    fn from(memory: &MemoryRecord) -> Self {
        Self {
            format: MEMORY_JSONL_FORMAT.to_owned(),
            format_version: MEMORY_JSONL_VERSION,
            workspace_id: memory.workspace_id().to_string(),
            subject_id: memory.subject_id().to_string(),
            memory_id: memory.id().to_string(),
            version: memory.version(),
            scope: PortableScope::from(memory.scope()),
            kind: PortableMemoryKind::from(memory.kind()),
            status: PortableMemoryStatus::from(memory.status()),
            content: memory.content().to_owned(),
            evidence: memory
                .evidence()
                .iter()
                .map(PortableEvidence::from)
                .collect(),
        }
    }
}

impl TryFrom<PortableMemoryRecord> for MemoryRecord {
    type Error = CodecError;

    fn try_from(memory: PortableMemoryRecord) -> Result<Self, Self::Error> {
        MemoryRecord::restore(
            MemoryId::new(memory.memory_id),
            WorkspaceId::new(memory.workspace_id),
            PrincipalId::new(memory.subject_id),
            MemoryScope::from(memory.scope),
            MemoryKind::from(memory.kind),
            MemoryStatus::from(memory.status),
            memory.content,
            memory.version,
            memory
                .evidence
                .into_iter()
                .map(EvidenceReference::from)
                .collect(),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&MemoryScope> for PortableScope {
    fn from(scope: &MemoryScope) -> Self {
        match scope {
            MemoryScope::Global => Self::Global,
            MemoryScope::Domain { name } => Self::Domain { name: name.clone() },
            MemoryScope::Entity { id } => Self::Entity { id: id.to_string() },
            MemoryScope::Activity { id } => Self::Activity { id: id.to_string() },
        }
    }
}

impl From<PortableScope> for MemoryScope {
    fn from(scope: PortableScope) -> Self {
        match scope {
            PortableScope::Global => Self::Global,
            PortableScope::Domain { name } => Self::Domain { name },
            PortableScope::Entity { id } => Self::Entity {
                id: EntityId::new(id),
            },
            PortableScope::Activity { id } => Self::Activity {
                id: ActivityId::new(id),
            },
        }
    }
}

impl From<MemoryKind> for PortableMemoryKind {
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

impl From<PortableMemoryKind> for MemoryKind {
    fn from(kind: PortableMemoryKind) -> Self {
        match kind {
            PortableMemoryKind::Preference => Self::Preference,
            PortableMemoryKind::Semantic => Self::Semantic,
            PortableMemoryKind::Episodic => Self::Episodic,
            PortableMemoryKind::Procedural => Self::Procedural,
            PortableMemoryKind::Observation => Self::Observation,
            PortableMemoryKind::Working => Self::Working,
        }
    }
}

impl From<MemoryStatus> for PortableMemoryStatus {
    fn from(status: MemoryStatus) -> Self {
        match status {
            MemoryStatus::Proposed => Self::Proposed,
            MemoryStatus::Confirmed => Self::Confirmed,
            MemoryStatus::Superseded => Self::Superseded,
            MemoryStatus::Deleted => Self::Deleted,
        }
    }
}

impl From<PortableMemoryStatus> for MemoryStatus {
    fn from(status: PortableMemoryStatus) -> Self {
        match status {
            PortableMemoryStatus::Proposed => Self::Proposed,
            PortableMemoryStatus::Confirmed => Self::Confirmed,
            PortableMemoryStatus::Superseded => Self::Superseded,
            PortableMemoryStatus::Deleted => Self::Deleted,
        }
    }
}

impl From<&EvidenceReference> for PortableEvidence {
    fn from(evidence: &EvidenceReference) -> Self {
        Self {
            id: evidence.id.to_string(),
            source: PortableEvidenceSource::from(evidence.source),
        }
    }
}

impl From<PortableEvidence> for EvidenceReference {
    fn from(evidence: PortableEvidence) -> Self {
        Self::new(
            EvidenceId::new(evidence.id),
            EvidenceSource::from(evidence.source),
        )
    }
}

impl From<EvidenceSource> for PortableEvidenceSource {
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

impl From<PortableEvidenceSource> for EvidenceSource {
    fn from(source: PortableEvidenceSource) -> Self {
        match source {
            PortableEvidenceSource::UserStatement => Self::UserStatement,
            PortableEvidenceSource::AgentObservation => Self::AgentObservation,
            PortableEvidenceSource::ToolResult => Self::ToolResult,
            PortableEvidenceSource::ImportedRecord => Self::ImportedRecord,
            PortableEvidenceSource::WorkspaceDecision => Self::WorkspaceDecision,
        }
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        EntityId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryRecord,
        MemoryScope, PrincipalId, WorkspaceId,
    };

    use super::{
        MAX_MEMORY_JSONL_ARCHIVE_BYTES, MAX_MEMORY_JSONL_ARCHIVE_RECORDS,
        MAX_MEMORY_JSONL_LINE_BYTES, decode_memory_jsonl_archive,
        decode_memory_jsonl_archive_with_limits, decode_memory_jsonl_record,
        encode_memory_jsonl_record,
    };
    use crate::CodecError;

    fn fixture() -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Entity {
                id: EntityId::new("project_01"),
            },
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("valid fixture")
    }

    #[test]
    fn round_trips_one_closed_versioned_jsonl_record() {
        let memory = fixture();
        let encoded = encode_memory_jsonl_record(&memory).expect("encode");

        assert!(encoded.ends_with(b"\n"));
        assert_eq!(
            decode_memory_jsonl_record(&encoded).expect("decode"),
            memory
        );
    }

    #[test]
    fn rejects_unknown_fields_formats_versions_and_oversized_lines() {
        let encoded = encode_memory_jsonl_record(&fixture()).expect("encode");
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON fixture");
        value["unexpected"] = serde_json::json!(true);
        assert_eq!(
            decode_memory_jsonl_record(&serde_json::to_vec(&value).expect("JSON")),
            Err(CodecError::MalformedPayload)
        );

        value.as_object_mut().expect("object").remove("unexpected");
        value["format"] = serde_json::json!("other");
        assert_eq!(
            decode_memory_jsonl_record(&serde_json::to_vec(&value).expect("JSON")),
            Err(CodecError::UnsupportedFormat)
        );
        value["format"] = serde_json::json!("rembrane-memory-jsonl");
        value["formatVersion"] = serde_json::json!(2);
        assert_eq!(
            decode_memory_jsonl_record(&serde_json::to_vec(&value).expect("JSON")),
            Err(CodecError::UnsupportedVersion)
        );
        assert_eq!(
            decode_memory_jsonl_record(&vec![b'x'; MAX_MEMORY_JSONL_LINE_BYTES + 1]),
            Err(CodecError::MalformedPayload)
        );
    }

    #[test]
    fn archive_decode_rejects_duplicates_mixed_tenants_and_blank_lines() {
        let memory = fixture();
        let line = encode_memory_jsonl_record(&memory).expect("encode");
        let mut duplicate = line.clone();
        duplicate.extend_from_slice(&line);
        assert_eq!(
            decode_memory_jsonl_archive(&duplicate),
            Err(CodecError::InvalidDomainRecord)
        );

        let foreign = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_02"),
            WorkspaceId::new("workspace_02"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Foreign tenant",
            EvidenceReference::new(
                EvidenceId::new("evidence_02"),
                EvidenceSource::ImportedRecord,
            ),
        )
        .expect("valid foreign fixture");
        let mut mixed = line;
        mixed.extend_from_slice(&encode_memory_jsonl_record(&foreign).expect("encode"));
        assert_eq!(
            decode_memory_jsonl_archive(&mixed),
            Err(CodecError::InvalidDomainRecord)
        );
        assert_eq!(
            decode_memory_jsonl_archive(b"\n"),
            Err(CodecError::MalformedPayload)
        );
    }

    #[test]
    fn archive_decode_enforces_global_record_and_byte_bounds() {
        let first = encode_memory_jsonl_record(&fixture()).expect("encode");
        let second = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_02"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Second",
            EvidenceReference::new(
                EvidenceId::new("evidence_02"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("valid fixture");
        let mut two_records = first;
        two_records.extend_from_slice(&encode_memory_jsonl_record(&second).expect("encode"));
        assert_eq!(
            decode_memory_jsonl_archive_with_limits(&two_records, 1, two_records.len()),
            Err(CodecError::MalformedPayload)
        );
        assert_eq!(
            decode_memory_jsonl_archive_with_limits(b"{}", MAX_MEMORY_JSONL_ARCHIVE_RECORDS, 1),
            Err(CodecError::MalformedPayload)
        );
        assert!(MAX_MEMORY_JSONL_ARCHIVE_BYTES > two_records.len());
    }
}
