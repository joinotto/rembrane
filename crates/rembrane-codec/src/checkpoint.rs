use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const CHECKPOINT_FORMAT: &str = "rembrane.activity-checkpoint";
const CHECKPOINT_FORMAT_VERSION: u16 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    format: String,
    version: u16,
    record: CheckpointDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDto {
    id: String,
    workspace_id: String,
    subject_id: String,
    activity_id: String,
    entity_id: Option<String>,
    goal: String,
    summary: String,
    next_steps: Vec<String>,
    blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_fingerprint: Option<String>,
    record_version: u64,
}

pub fn encode_checkpoint(checkpoint: &ActivityCheckpoint) -> Result<Vec<u8>, CodecError> {
    let envelope = CheckpointEnvelope {
        format: CHECKPOINT_FORMAT.to_owned(),
        version: CHECKPOINT_FORMAT_VERSION,
        record: CheckpointDto::from(checkpoint),
    };

    serde_json::to_vec(&envelope).map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_checkpoint(payload: &[u8]) -> Result<ActivityCheckpoint, CodecError> {
    let envelope: CheckpointEnvelope =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if envelope.format != CHECKPOINT_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if envelope.version != CHECKPOINT_FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }

    ActivityCheckpoint::try_from(envelope.record)
}

impl From<&ActivityCheckpoint> for CheckpointDto {
    fn from(checkpoint: &ActivityCheckpoint) -> Self {
        Self {
            id: checkpoint.id().as_str().to_owned(),
            workspace_id: checkpoint.workspace_id().as_str().to_owned(),
            subject_id: checkpoint.subject_id().as_str().to_owned(),
            activity_id: checkpoint.activity_id().as_str().to_owned(),
            entity_id: checkpoint
                .entity_id()
                .map(|entity| entity.as_str().to_owned()),
            goal: checkpoint.goal().to_owned(),
            summary: checkpoint.summary().to_owned(),
            next_steps: checkpoint.next_steps().to_vec(),
            blockers: checkpoint.blockers().to_vec(),
            state_fingerprint: checkpoint.state_fingerprint().map(str::to_owned),
            record_version: checkpoint.version(),
        }
    }
}

impl TryFrom<CheckpointDto> for ActivityCheckpoint {
    type Error = CodecError;

    fn try_from(checkpoint: CheckpointDto) -> Result<Self, Self::Error> {
        Self::restore(
            CheckpointId::new(checkpoint.id),
            WorkspaceId::new(checkpoint.workspace_id),
            PrincipalId::new(checkpoint.subject_id),
            ActivityId::new(checkpoint.activity_id),
            checkpoint.entity_id.map(EntityId::new),
            checkpoint.goal,
            checkpoint.summary,
            checkpoint.next_steps,
            checkpoint.blockers,
            checkpoint.state_fingerprint,
            checkpoint.record_version,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        ActivityCheckpoint, ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId,
    };

    use super::{decode_checkpoint, encode_checkpoint};

    fn checkpoint() -> ActivityCheckpoint {
        ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            Some(EntityId::new("project_01")),
            "Implement authentication",
            "Callback implemented and unit tested.",
            vec!["Run integration tests".to_owned()],
            vec!["Need staging credentials".to_owned()],
        )
        .expect("fixture is valid")
    }

    #[test]
    fn round_trips_activity_checkpoint() {
        let original = checkpoint();
        let encoded = encode_checkpoint(&original).expect("encoding succeeds");
        let decoded = decode_checkpoint(&encoded).expect("decoding succeeds");

        assert_eq!(decoded, original);
    }

    #[test]
    fn preserves_checkpoint_v1_wire_fixture() {
        let encoded = encode_checkpoint(&checkpoint()).expect("encoding succeeds");
        let expected = include_str!("../fixtures/checkpoint-v1-project-handoff.json")
            .trim_end()
            .as_bytes();

        assert_eq!(encoded, expected);
    }
}
