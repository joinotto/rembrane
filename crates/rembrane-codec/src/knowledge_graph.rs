use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode,
    KnowledgeNodeId, KnowledgeNodeKind, KnowledgeRelationType, TemporalValidity, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::CodecError;

const NODE_FORMAT: &str = "rembrane.knowledge-node";
const EDGE_FORMAT: &str = "rembrane.knowledge-edge";
pub const KNOWLEDGE_GRAPH_ARCHIVE_FORMAT: &str = "rembrane.knowledge-graph";
pub const KNOWLEDGE_GRAPH_ARCHIVE_VERSION: u16 = 1;
pub const MAX_KNOWLEDGE_GRAPH_ARCHIVE_BYTES: usize = 67_108_864;
pub const MAX_KNOWLEDGE_GRAPH_ARCHIVE_RECORDS: usize = 20_000;
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
struct GraphArchiveDto {
    format: String,
    version: u16,
    workspace_id: String,
    nodes: Vec<NodeDto>,
    edges: Vec<EdgeDto>,
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
    #[serde(rename = "valid_from_epoch_seconds")]
    valid_from: u64,
    #[serde(rename = "valid_until_epoch_seconds")]
    valid_until: Option<u64>,
    #[serde(rename = "recorded_at_epoch_seconds")]
    recorded_at: u64,
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

pub fn encode_knowledge_graph_archive(
    workspace_id: &WorkspaceId,
    nodes: &[KnowledgeNode],
    edges: &[KnowledgeEdge],
) -> Result<Vec<u8>, CodecError> {
    validate_graph_archive(workspace_id, nodes, edges)?;
    let mut nodes = nodes.iter().map(NodeDto::from).collect::<Vec<_>>();
    nodes.sort_unstable_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.record_version.cmp(&right.record_version))
    });
    let mut edges = edges.iter().map(EdgeDto::from).collect::<Vec<_>>();
    edges.sort_unstable_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.record_version.cmp(&right.record_version))
    });
    let encoded = serde_json::to_vec(&GraphArchiveDto {
        format: KNOWLEDGE_GRAPH_ARCHIVE_FORMAT.to_owned(),
        version: KNOWLEDGE_GRAPH_ARCHIVE_VERSION,
        workspace_id: workspace_id.as_str().to_owned(),
        nodes,
        edges,
    })
    .map_err(|_| CodecError::MalformedPayload)?;
    if encoded.len() > MAX_KNOWLEDGE_GRAPH_ARCHIVE_BYTES {
        return Err(CodecError::MalformedPayload);
    }
    Ok(encoded)
}

pub fn decode_knowledge_graph_archive(
    payload: &[u8],
) -> Result<(WorkspaceId, Vec<KnowledgeNode>, Vec<KnowledgeEdge>), CodecError> {
    if payload.is_empty() || payload.len() > MAX_KNOWLEDGE_GRAPH_ARCHIVE_BYTES {
        return Err(CodecError::MalformedPayload);
    }
    let archive: GraphArchiveDto =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    validate_envelope(
        &archive.format,
        archive.version,
        KNOWLEDGE_GRAPH_ARCHIVE_FORMAT,
    )?;
    let workspace_id = WorkspaceId::new(archive.workspace_id);
    let nodes = archive
        .nodes
        .into_iter()
        .map(KnowledgeNode::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let edges = archive
        .edges
        .into_iter()
        .map(KnowledgeEdge::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    validate_graph_archive(&workspace_id, &nodes, &edges)?;
    Ok((workspace_id, nodes, edges))
}

fn validate_graph_archive(
    workspace_id: &WorkspaceId,
    nodes: &[KnowledgeNode],
    edges: &[KnowledgeEdge],
) -> Result<(), CodecError> {
    if nodes
        .len()
        .checked_add(edges.len())
        .is_none_or(|count| count > MAX_KNOWLEDGE_GRAPH_ARCHIVE_RECORDS)
    {
        return Err(CodecError::MalformedPayload);
    }
    let mut node_revisions = HashSet::new();
    let mut node_ids = HashSet::new();
    for node in nodes {
        if node.workspace_id() != workspace_id
            || !node_revisions.insert((node.id().as_str(), node.version()))
        {
            return Err(CodecError::InvalidDomainRecord);
        }
        node_ids.insert(node.id().as_str());
    }
    let mut edge_revisions = HashSet::new();
    for edge in edges {
        if edge.workspace_id() != workspace_id
            || !edge_revisions.insert((edge.id().as_str(), edge.version()))
            || !node_ids.contains(edge.source_id().as_str())
            || !node_ids.contains(edge.target_id().as_str())
        {
            return Err(CodecError::InvalidDomainRecord);
        }
    }
    Ok(())
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
            valid_from: validity.valid_from_epoch_seconds(),
            valid_until: validity.valid_until_epoch_seconds(),
            recorded_at: validity.recorded_at_epoch_seconds(),
        }
    }
}

impl TryFrom<ValidityDto> for TemporalValidity {
    type Error = CodecError;

    fn try_from(validity: ValidityDto) -> Result<Self, Self::Error> {
        Self::new(
            validity.valid_from,
            validity.valid_until,
            validity.recorded_at,
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
        KNOWLEDGE_GRAPH_ARCHIVE_FORMAT, decode_knowledge_edge, decode_knowledge_graph_archive,
        decode_knowledge_node, encode_knowledge_edge, encode_knowledge_graph_archive,
        encode_knowledge_node,
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

    #[test]
    fn graph_archive_round_trips_in_deterministic_order() {
        let workspace = WorkspaceId::new("workspace_01");
        let validity = TemporalValidity::new(100, Some(200), 150).expect("validity should work");
        let project = KnowledgeNode::new(
            KnowledgeNodeId::new("node_project"),
            workspace.clone(),
            KnowledgeNodeKind::Project,
            "Rembrane".to_owned(),
            vec!["Central memory".to_owned()],
            vec![evidence("evidence_project")],
            validity,
            2,
        )
        .expect("project node");
        let rust = KnowledgeNode::new(
            KnowledgeNodeId::new("node_rust"),
            workspace.clone(),
            KnowledgeNodeKind::Concept,
            "Rust".to_owned(),
            Vec::new(),
            vec![evidence("evidence_rust")],
            validity,
            1,
        )
        .expect("Rust node");
        let edge = KnowledgeEdge::new(
            KnowledgeEdgeId::new("edge_uses"),
            workspace.clone(),
            project.id().clone(),
            rust.id().clone(),
            KnowledgeRelationType::new("uses").expect("relation"),
            vec![evidence("evidence_edge")],
            validity,
            1,
            None,
        )
        .expect("edge");

        let encoded =
            encode_knowledge_graph_archive(&workspace, &[rust.clone(), project.clone()], &[edge])
                .expect("archive encoding");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("archive JSON");
        assert_eq!(value["format"], KNOWLEDGE_GRAPH_ARCHIVE_FORMAT);
        assert_eq!(value["nodes"][0]["id"], "node_project");
        assert_eq!(value["nodes"][1]["id"], "node_rust");

        let (decoded_workspace, nodes, edges) =
            decode_knowledge_graph_archive(&encoded).expect("archive decoding");
        assert_eq!(decoded_workspace, workspace);
        assert_eq!(nodes, vec![project, rust]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].id().as_str(), "edge_uses");
    }

    #[test]
    fn graph_archive_rejects_cross_tenant_and_dangling_edges() {
        let workspace = WorkspaceId::new("workspace_01");
        let validity = TemporalValidity::new(100, None, 150).expect("validity should work");
        let foreign = KnowledgeNode::new(
            KnowledgeNodeId::new("node_foreign"),
            WorkspaceId::new("workspace_other"),
            KnowledgeNodeKind::Concept,
            "Foreign".to_owned(),
            Vec::new(),
            vec![evidence("evidence_foreign")],
            validity,
            1,
        )
        .expect("foreign node");
        assert_eq!(
            encode_knowledge_graph_archive(&workspace, &[foreign], &[]),
            Err(crate::CodecError::InvalidDomainRecord)
        );

        let local = KnowledgeNode::new(
            KnowledgeNodeId::new("node_local"),
            workspace.clone(),
            KnowledgeNodeKind::Project,
            "Local".to_owned(),
            Vec::new(),
            vec![evidence("evidence_local")],
            validity,
            1,
        )
        .expect("local node");
        let dangling = KnowledgeEdge::new(
            KnowledgeEdgeId::new("edge_dangling"),
            workspace.clone(),
            local.id().clone(),
            KnowledgeNodeId::new("node_missing"),
            KnowledgeRelationType::new("uses").expect("relation"),
            vec![evidence("evidence_dangling")],
            validity,
            1,
            None,
        )
        .expect("domain-valid edge");
        assert_eq!(
            encode_knowledge_graph_archive(&workspace, &[local], &[dangling]),
            Err(crate::CodecError::InvalidDomainRecord)
        );
    }
}
