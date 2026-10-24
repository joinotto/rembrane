use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode,
    KnowledgeNodeId, KnowledgeNodeKind, KnowledgeRelationType, TemporalValidity, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const NODE_FORMAT: &str = "rembrane.knowledge-node";
const EDGE_FORMAT: &str = "rembrane.knowledge-edge";
const FORMAT_VERSION: u16 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    format: String,
    version: u16,
    record: T,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeDto {
    id: String,
    workspace_id: String,
    kind: NodeKindDto,
    label: String,
    aliases: Vec<String>,
    evidence: Vec<EvidenceDto>,
    validity: ValidityDto,
    record_version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EdgeDto {
    id: String,
    workspace_id: String,
    source_id: String,
    target_id: String,
    relation: String,
    evidence: Vec<EvidenceDto>,
    validity: ValidityDto,
    record_version: u64,
    supersedes_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum NodeKindDto {
    Person,
    Organization,
    Place,
    Project,
    Artifact,
    Concept,
    Event,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidityDto {
    valid_from_epoch_seconds: u64,
    valid_until_epoch_seconds: Option<u64>,
    recorded_at_epoch_seconds: u64,
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

pub fn encode_knowledge_node(node: &KnowledgeNode) -> Result<Vec<u8>, CodecError> {
    serde_json::to_vec(&Envelope {
        format: NODE_FORMAT.to_owned(),
        version: FORMAT_VERSION,
        record: NodeDto::from(node),
    })
    .map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_knowledge_node(payload: &[u8]) -> Result<KnowledgeNode, CodecError> {
    let envelope: Envelope<NodeDto> =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    validate_envelope(&envelope.format, envelope.version, NODE_FORMAT)?;
    KnowledgeNode::try_from(envelope.record)
}

pub fn encode_knowledge_edge(edge: &KnowledgeEdge) -> Result<Vec<u8>, CodecError> {
    serde_json::to_vec(&Envelope {
        format: EDGE_FORMAT.to_owned(),
        version: FORMAT_VERSION,
        record: EdgeDto::from(edge),
    })
    .map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_knowledge_edge(payload: &[u8]) -> Result<KnowledgeEdge, CodecError> {
    let envelope: Envelope<EdgeDto> =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    validate_envelope(&envelope.format, envelope.version, EDGE_FORMAT)?;
    KnowledgeEdge::try_from(envelope.record)
}

fn validate_envelope(format: &str, version: u16, expected: &str) -> Result<(), CodecError> {
    if format != expected {
        return Err(CodecError::UnsupportedFormat);
    }
    if version != FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    Ok(())
}

impl From<&KnowledgeNode> for NodeDto {
    fn from(node: &KnowledgeNode) -> Self {
        Self {
            id: node.id().as_str().to_owned(),
            workspace_id: node.workspace_id().as_str().to_owned(),
            kind: NodeKindDto::from(node.kind()),
            label: node.label().to_owned(),
            aliases: node.aliases().to_vec(),
            evidence: node.evidence().iter().map(EvidenceDto::from).collect(),
            validity: ValidityDto::from(node.validity()),
            record_version: node.version(),
        }
    }
}

impl TryFrom<NodeDto> for KnowledgeNode {
    type Error = CodecError;

    fn try_from(node: NodeDto) -> Result<Self, Self::Error> {
        KnowledgeNode::new(
            KnowledgeNodeId::new(node.id),
            WorkspaceId::new(node.workspace_id),
            KnowledgeNodeKind::from(node.kind),
            node.label,
            node.aliases,
            node.evidence
                .into_iter()
                .map(EvidenceReference::from)
                .collect(),
            TemporalValidity::try_from(node.validity)?,
            node.record_version,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&KnowledgeEdge> for EdgeDto {
    fn from(edge: &KnowledgeEdge) -> Self {
        Self {
            id: edge.id().as_str().to_owned(),
            workspace_id: edge.workspace_id().as_str().to_owned(),
            source_id: edge.source_id().as_str().to_owned(),
            target_id: edge.target_id().as_str().to_owned(),
            relation: edge.relation().as_str().to_owned(),
            evidence: edge.evidence().iter().map(EvidenceDto::from).collect(),
            validity: ValidityDto::from(edge.validity()),
            record_version: edge.version(),
            supersedes_id: edge
                .supersedes()
                .map(|identifier| identifier.as_str().to_owned()),
        }
    }
}

impl TryFrom<EdgeDto> for KnowledgeEdge {
    type Error = CodecError;

    fn try_from(edge: EdgeDto) -> Result<Self, Self::Error> {
        KnowledgeEdge::new(
            KnowledgeEdgeId::new(edge.id),
            WorkspaceId::new(edge.workspace_id),
            KnowledgeNodeId::new(edge.source_id),
            KnowledgeNodeId::new(edge.target_id),
            KnowledgeRelationType::new(edge.relation)
                .map_err(|_| CodecError::InvalidDomainRecord)?,
            edge.evidence
                .into_iter()
                .map(EvidenceReference::from)
                .collect(),
            TemporalValidity::try_from(edge.validity)?,
            edge.record_version,
            edge.supersedes_id.map(KnowledgeEdgeId::new),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<KnowledgeNodeKind> for NodeKindDto {
    fn from(kind: KnowledgeNodeKind) -> Self {
        match kind {
            KnowledgeNodeKind::Person => Self::Person,
            KnowledgeNodeKind::Organization => Self::Organization,
            KnowledgeNodeKind::Place => Self::Place,
            KnowledgeNodeKind::Project => Self::Project,
            KnowledgeNodeKind::Artifact => Self::Artifact,
            KnowledgeNodeKind::Concept => Self::Concept,
            KnowledgeNodeKind::Event => Self::Event,
        }
    }
}

impl From<NodeKindDto> for KnowledgeNodeKind {
    fn from(kind: NodeKindDto) -> Self {
        match kind {
            NodeKindDto::Person => Self::Person,
            NodeKindDto::Organization => Self::Organization,
            NodeKindDto::Place => Self::Place,
            NodeKindDto::Project => Self::Project,
            NodeKindDto::Artifact => Self::Artifact,
            NodeKindDto::Concept => Self::Concept,
            NodeKindDto::Event => Self::Event,
        }
    }
}

impl From<TemporalValidity> for ValidityDto {
    fn from(validity: TemporalValidity) -> Self {
        Self {
            valid_from_epoch_seconds: validity.valid_from_epoch_seconds(),
            valid_until_epoch_seconds: validity.valid_until_epoch_seconds(),
            recorded_at_epoch_seconds: validity.recorded_at_epoch_seconds(),
        }
    }
}

impl TryFrom<ValidityDto> for TemporalValidity {
    type Error = CodecError;

    fn try_from(validity: ValidityDto) -> Result<Self, Self::Error> {
        Self::new(
            validity.valid_from_epoch_seconds,
            validity.valid_until_epoch_seconds,
            validity.recorded_at_epoch_seconds,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
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
    use rembrane_domain::{
        EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdge, KnowledgeEdgeId,
        KnowledgeNode, KnowledgeNodeId, KnowledgeNodeKind, KnowledgeRelationType, TemporalValidity,
        WorkspaceId,
    };

    use super::{
        decode_knowledge_edge, decode_knowledge_node, encode_knowledge_edge, encode_knowledge_node,
    };

    fn evidence(id: &str) -> EvidenceReference {
        EvidenceReference::new(EvidenceId::new(id), EvidenceSource::UserStatement)
    }

    #[test]
    fn round_trips_node_and_edge_without_losing_temporal_provenance() {
        let validity = TemporalValidity::new(100, Some(200), 150).expect("validity should work");
        let node = KnowledgeNode::new(
            KnowledgeNodeId::new("node_project"),
            WorkspaceId::new("workspace_01"),
            KnowledgeNodeKind::Project,
            "Rembrane".to_owned(),
            vec!["Central memory".to_owned()],
            vec![evidence("evidence_node")],
            validity,
            2,
        )
        .expect("node should be valid");
        let edge = KnowledgeEdge::new(
            KnowledgeEdgeId::new("edge_uses"),
            WorkspaceId::new("workspace_01"),
            KnowledgeNodeId::new("node_project"),
            KnowledgeNodeId::new("node_rust"),
            KnowledgeRelationType::new("uses").expect("relation should be valid"),
            vec![evidence("evidence_edge")],
            validity,
            3,
            Some(KnowledgeEdgeId::new("edge_old")),
        )
        .expect("edge should be valid");

        assert_eq!(
            decode_knowledge_node(&encode_knowledge_node(&node).expect("node should encode"))
                .expect("node should decode"),
            node
        );
        assert_eq!(
            decode_knowledge_edge(&encode_knowledge_edge(&edge).expect("edge should encode"))
                .expect("edge should decode"),
            edge
        );
    }
}
