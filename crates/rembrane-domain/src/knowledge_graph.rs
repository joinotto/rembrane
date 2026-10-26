use std::error::Error;
use std::fmt::{self, Display};

use crate::{EvidenceReference, KnowledgeEdgeId, KnowledgeNodeId, WorkspaceId};

pub const MAX_KNOWLEDGE_LABEL_BYTES: usize = 1024;
pub const MAX_KNOWLEDGE_ALIASES: usize = 50;
pub const MAX_KNOWLEDGE_EVIDENCE: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeNodeKind {
    Person,
    Organization,
    Place,
    Project,
    Artifact,
    Concept,
    Event,
}

#[derive(Clone, Eq, PartialEq)]
pub struct KnowledgeRelationType(String);

impl fmt::Debug for KnowledgeRelationType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KnowledgeRelationType")
            .field(&"<redacted>")
            .finish()
    }
}

impl KnowledgeRelationType {
    /// Creates a portable namespaced or built-in relationship type.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value contains 2-100 lowercase ASCII
    /// letters, digits, dots, underscores, hyphens, or colons.
    pub fn new(value: impl Into<String>) -> Result<Self, KnowledgeGraphError> {
        let value = value.into();
        if !(2..=100).contains(&value.len())
            || !value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-' | b':'))
            })
        {
            return Err(KnowledgeGraphError::InvalidRelationType);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TemporalValidity {
    valid_from: u64,
    valid_until: Option<u64>,
    recorded_at: u64,
}

impl fmt::Debug for TemporalValidity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemporalValidity")
            .field("valid_from", &"<redacted>")
            .field("valid_until_present", &self.valid_until.is_some())
            .field("recorded_at", &"<redacted>")
            .finish()
    }
}

impl TemporalValidity {
    /// Creates separate event-time validity and system ingestion time.
    ///
    /// # Errors
    ///
    /// Returns an error for zero timestamps or a validity end that is not
    /// strictly later than its start.
    pub fn new(
        valid_from_epoch_seconds: u64,
        valid_until_epoch_seconds: Option<u64>,
        recorded_at_epoch_seconds: u64,
    ) -> Result<Self, KnowledgeGraphError> {
        if valid_from_epoch_seconds == 0
            || recorded_at_epoch_seconds == 0
            || valid_until_epoch_seconds
                .is_some_and(|valid_until| valid_until <= valid_from_epoch_seconds)
        {
            return Err(KnowledgeGraphError::InvalidValidity);
        }
        Ok(Self {
            valid_from: valid_from_epoch_seconds,
            valid_until: valid_until_epoch_seconds,
            recorded_at: recorded_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn valid_from_epoch_seconds(self) -> u64 {
        self.valid_from
    }

    #[must_use]
    pub const fn valid_until_epoch_seconds(self) -> Option<u64> {
        self.valid_until
    }

    #[must_use]
    pub const fn recorded_at_epoch_seconds(self) -> u64 {
        self.recorded_at
    }

    #[must_use]
    pub fn contains(self, epoch_seconds: u64) -> bool {
        epoch_seconds >= self.valid_from
            && self
                .valid_until
                .is_none_or(|valid_until| epoch_seconds < valid_until)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KnowledgeNode {
    id: KnowledgeNodeId,
    workspace_id: WorkspaceId,
    kind: KnowledgeNodeKind,
    label: String,
    aliases: Vec<String>,
    evidence: Vec<EvidenceReference>,
    validity: TemporalValidity,
    version: u64,
}

impl fmt::Debug for KnowledgeNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KnowledgeNode")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("kind", &self.kind)
            .field("label_bytes", &self.label.len())
            .field("alias_count", &self.aliases.len())
            .field(
                "alias_bytes",
                &self.aliases.iter().map(String::len).sum::<usize>(),
            )
            .field("evidence_count", &self.evidence.len())
            .field("validity", &self.validity)
            .field("version", &self.version)
            .finish()
    }
}

impl KnowledgeNode {
    /// Creates one evidence-backed typed node in an exact workspace namespace.
    ///
    /// Aliases remain labels only; they never imply an automatic node merge.
    ///
    /// # Errors
    ///
    /// Returns an error for empty identity, invalid labels, duplicate aliases
    /// or evidence, excessive collections, or a zero version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: KnowledgeNodeId,
        workspace_id: WorkspaceId,
        kind: KnowledgeNodeKind,
        label: String,
        aliases: Vec<String>,
        evidence: Vec<EvidenceReference>,
        validity: TemporalValidity,
        version: u64,
    ) -> Result<Self, KnowledgeGraphError> {
        validate_identity(id.as_str(), workspace_id.as_str())?;
        validate_label(&label)?;
        if aliases.len() > MAX_KNOWLEDGE_ALIASES
            || aliases
                .iter()
                .any(|alias| validate_label(alias).is_err() || alias == &label)
            || contains_duplicate(&aliases)
        {
            return Err(KnowledgeGraphError::InvalidAliases);
        }
        validate_evidence(&evidence)?;
        if version == 0 {
            return Err(KnowledgeGraphError::InvalidVersion);
        }
        Ok(Self {
            id,
            workspace_id,
            kind,
            label,
            aliases,
            evidence,
            validity,
            version,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &KnowledgeNodeId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn kind(&self) -> KnowledgeNodeKind {
        self.kind
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }

    #[must_use]
    pub const fn validity(&self) -> TemporalValidity {
        self.validity
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KnowledgeEdge {
    id: KnowledgeEdgeId,
    workspace_id: WorkspaceId,
    source_id: KnowledgeNodeId,
    target_id: KnowledgeNodeId,
    relation: KnowledgeRelationType,
    evidence: Vec<EvidenceReference>,
    validity: TemporalValidity,
    version: u64,
    supersedes: Option<KnowledgeEdgeId>,
}

impl fmt::Debug for KnowledgeEdge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KnowledgeEdge")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("source_id", &"<redacted>")
            .field("target_id", &"<redacted>")
            .field("relation", &self.relation)
            .field("evidence_count", &self.evidence.len())
            .field("validity", &self.validity)
            .field("version", &self.version)
            .field("supersedes_present", &self.supersedes.is_some())
            .finish()
    }
}

impl KnowledgeEdge {
    /// Creates one temporal, evidence-backed relationship.
    ///
    /// Endpoint workspace membership and supersession lineage are enforced by
    /// the canonical repository transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for empty identity, identical endpoints, invalid
    /// evidence, a zero version, or self-supersession.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: KnowledgeEdgeId,
        workspace_id: WorkspaceId,
        source_id: KnowledgeNodeId,
        target_id: KnowledgeNodeId,
        relation: KnowledgeRelationType,
        evidence: Vec<EvidenceReference>,
        validity: TemporalValidity,
        version: u64,
        supersedes: Option<KnowledgeEdgeId>,
    ) -> Result<Self, KnowledgeGraphError> {
        validate_identity(id.as_str(), workspace_id.as_str())?;
        if source_id.as_str().is_empty() || target_id.as_str().is_empty() || source_id == target_id
        {
            return Err(KnowledgeGraphError::InvalidEndpoints);
        }
        validate_evidence(&evidence)?;
        if version == 0 {
            return Err(KnowledgeGraphError::InvalidVersion);
        }
        if supersedes
            .as_ref()
            .is_some_and(|superseded| superseded.as_str().is_empty() || superseded == &id)
        {
            return Err(KnowledgeGraphError::InvalidSupersession);
        }
        Ok(Self {
            id,
            workspace_id,
            source_id,
            target_id,
            relation,
            evidence,
            validity,
            version,
            supersedes,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &KnowledgeEdgeId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn source_id(&self) -> &KnowledgeNodeId {
        &self.source_id
    }

    #[must_use]
    pub const fn target_id(&self) -> &KnowledgeNodeId {
        &self.target_id
    }

    #[must_use]
    pub const fn relation(&self) -> &KnowledgeRelationType {
        &self.relation
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }

    #[must_use]
    pub const fn validity(&self) -> TemporalValidity {
        self.validity
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn supersedes(&self) -> Option<&KnowledgeEdgeId> {
        self.supersedes.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeGraphError {
    InvalidAliases,
    InvalidEndpoints,
    InvalidEvidence,
    InvalidIdentity,
    InvalidLabel,
    InvalidRelationType,
    InvalidSupersession,
    InvalidValidity,
    InvalidVersion,
}

impl Display for KnowledgeGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAliases => "knowledge node aliases are invalid",
            Self::InvalidEndpoints => "knowledge edge endpoints are invalid",
            Self::InvalidEvidence => "knowledge graph evidence is invalid",
            Self::InvalidIdentity => "knowledge graph identity is invalid",
            Self::InvalidLabel => "knowledge node label is invalid",
            Self::InvalidRelationType => "knowledge relation type is invalid",
            Self::InvalidSupersession => "knowledge edge supersession is invalid",
            Self::InvalidValidity => "knowledge graph temporal validity is invalid",
            Self::InvalidVersion => "knowledge graph version is invalid",
        })
    }
}

impl Error for KnowledgeGraphError {}

fn validate_identity(id: &str, workspace_id: &str) -> Result<(), KnowledgeGraphError> {
    if id.is_empty() || workspace_id.is_empty() {
        return Err(KnowledgeGraphError::InvalidIdentity);
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<(), KnowledgeGraphError> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > MAX_KNOWLEDGE_LABEL_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(KnowledgeGraphError::InvalidLabel);
    }
    Ok(())
}

fn validate_evidence(evidence: &[EvidenceReference]) -> Result<(), KnowledgeGraphError> {
    if evidence.is_empty()
        || evidence.len() > MAX_KNOWLEDGE_EVIDENCE
        || evidence.iter().any(|item| item.id.as_str().is_empty())
        || evidence
            .iter()
            .enumerate()
            .any(|(index, item)| evidence[..index].iter().any(|seen| seen.id == item.id))
    {
        return Err(KnowledgeGraphError::InvalidEvidence);
    }
    Ok(())
}

fn contains_duplicate<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[cfg(test)]
mod tests {
    use super::{
        KnowledgeEdge, KnowledgeGraphError, KnowledgeNode, KnowledgeNodeKind,
        KnowledgeRelationType, TemporalValidity,
    };
    use crate::{
        EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdgeId, KnowledgeNodeId,
        WorkspaceId,
    };

    fn evidence(id: &str) -> EvidenceReference {
        EvidenceReference::new(EvidenceId::new(id), EvidenceSource::UserStatement)
    }

    fn validity() -> TemporalValidity {
        TemporalValidity::new(100, Some(200), 150).expect("validity should be valid")
    }

    #[test]
    fn models_typed_workspace_scoped_temporal_knowledge() {
        let node = KnowledgeNode::new(
            KnowledgeNodeId::new("node_project"),
            WorkspaceId::new("workspace_01"),
            KnowledgeNodeKind::Project,
            "Rembrane".to_owned(),
            vec!["Central memory framework".to_owned()],
            vec![evidence("evidence_node")],
            validity(),
            1,
        )
        .expect("node should validate");
        let edge = KnowledgeEdge::new(
            KnowledgeEdgeId::new("edge_uses"),
            WorkspaceId::new("workspace_01"),
            KnowledgeNodeId::new("node_project"),
            KnowledgeNodeId::new("node_rust"),
            KnowledgeRelationType::new("uses").expect("relation should validate"),
            vec![evidence("evidence_edge")],
            validity(),
            1,
            None,
        )
        .expect("edge should validate");

        assert_eq!(node.kind(), KnowledgeNodeKind::Project);
        assert_eq!(edge.relation().as_str(), "uses");
        assert!(edge.validity().contains(100));
        assert!(!edge.validity().contains(200));
    }

    #[test]
    fn aliases_never_implicitly_merge_or_duplicate_labels() {
        let result = KnowledgeNode::new(
            KnowledgeNodeId::new("node_project"),
            WorkspaceId::new("workspace_01"),
            KnowledgeNodeKind::Project,
            "Rembrane".to_owned(),
            vec!["Rembrane".to_owned()],
            vec![evidence("evidence_node")],
            validity(),
            1,
        );
        assert_eq!(result, Err(KnowledgeGraphError::InvalidAliases));
    }

    #[test]
    fn rejects_invalid_time_relation_evidence_and_supersession() {
        assert_eq!(
            TemporalValidity::new(100, Some(100), 150),
            Err(KnowledgeGraphError::InvalidValidity)
        );
        assert_eq!(
            KnowledgeRelationType::new("Unsafe Relation"),
            Err(KnowledgeGraphError::InvalidRelationType)
        );
        assert_eq!(
            KnowledgeEdge::new(
                KnowledgeEdgeId::new("edge_uses"),
                WorkspaceId::new("workspace_01"),
                KnowledgeNodeId::new("node_project"),
                KnowledgeNodeId::new("node_rust"),
                KnowledgeRelationType::new("uses").expect("relation should validate"),
                Vec::new(),
                validity(),
                1,
                Some(KnowledgeEdgeId::new("edge_uses")),
            ),
            Err(KnowledgeGraphError::InvalidEvidence)
        );
        assert_eq!(
            KnowledgeEdge::new(
                KnowledgeEdgeId::new("edge_uses"),
                WorkspaceId::new("workspace_01"),
                KnowledgeNodeId::new("node_project"),
                KnowledgeNodeId::new("node_rust"),
                KnowledgeRelationType::new("uses").expect("relation should validate"),
                vec![evidence("evidence_edge")],
                validity(),
                1,
                Some(KnowledgeEdgeId::new("edge_uses")),
            ),
            Err(KnowledgeGraphError::InvalidSupersession)
        );
    }

    #[test]
    fn debug_output_redacts_graph_semantics_timeline_and_identities() {
        let validity = TemporalValidity::new(1_900_000_001, Some(1_900_000_999), 1_900_000_123)
            .expect("validity should be valid");
        let node = KnowledgeNode::new(
            KnowledgeNodeId::new("private_node"),
            WorkspaceId::new("private_workspace"),
            KnowledgeNodeKind::Project,
            "Private project label".to_owned(),
            vec!["Private project alias".to_owned()],
            vec![evidence("private_node_evidence")],
            validity,
            2,
        )
        .expect("node should validate");
        let relation =
            KnowledgeRelationType::new("private:depends_on").expect("relation should validate");
        let edge = KnowledgeEdge::new(
            KnowledgeEdgeId::new("private_edge"),
            WorkspaceId::new("private_workspace"),
            KnowledgeNodeId::new("private_source"),
            KnowledgeNodeId::new("private_target"),
            relation.clone(),
            vec![evidence("private_edge_evidence")],
            validity,
            3,
            Some(KnowledgeEdgeId::new("private_superseded_edge")),
        )
        .expect("edge should validate");

        let diagnostic = format!("{validity:?} {relation:?} {node:?} {edge:?}");

        for private_value in [
            "1900000001",
            "1900000999",
            "1900000123",
            "private_node",
            "private_workspace",
            "Private project label",
            "Private project alias",
            "private_node_evidence",
            "private:depends_on",
            "private_edge",
            "private_source",
            "private_target",
            "private_edge_evidence",
            "private_superseded_edge",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("valid_until_present: true"));
        assert!(diagnostic.contains("kind: Project"));
        assert!(diagnostic.contains("label_bytes: 21"));
        assert!(diagnostic.contains("alias_count: 1"));
        assert!(diagnostic.contains("evidence_count: 1"));
        assert!(diagnostic.contains("version: 2"));
        assert!(diagnostic.contains("version: 3"));
        assert!(diagnostic.contains("supersedes_present: true"));
    }
}
