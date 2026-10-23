use rembrane_application::{
    ApplicationError, ConfirmMemoryCommand, MemoryProposalService,
    ProposeMemoryCommand,
};
use rembrane_domain::{
    ClientId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryKind, MemoryScope, MemoryStatus, PrincipalId, WorkspaceId,
    WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn grant(subject_id: &str, permissions: Vec<WritePermission>) -> WriteGrant {
    WriteGrant {
        client_id: ClientId::new("assistant_01"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new(subject_id),
        permissions,
    }
}

fn evidence(id: &str, source: EvidenceSource) -> EvidenceReference {
    EvidenceReference::new(EvidenceId::new(id), source)
}

#[test]
fn agent_proposal_remains_unconfirmed_until_approved() {
    let mut store = InMemoryStore::new();
    let mut service = MemoryProposalService::new(&mut store);
    let proposal = service
        .propose(ProposeMemoryCommand {
            grant: grant(
                "principal_01",
                vec![WritePermission::ProposeMemory],
            ),
            memory_id: MemoryId::new("memory_01"),
            scope: MemoryScope::Global,
            kind: MemoryKind::Observation,
            content: "The user may prefer aisle seats.".to_owned(),
            evidence: evidence(
                "evidence_agent",
                EvidenceSource::AgentObservation,
            ),
        })
        .expect("authorized proposal should succeed");

    assert_eq!(proposal.status(), MemoryStatus::Proposed);

    let confirmed = service
        .confirm(ConfirmMemoryCommand {
            grant: grant(
                "principal_01",
                vec![WritePermission::ConfirmMemory],
            ),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            evidence: evidence(
                "evidence_user",
                EvidenceSource::UserStatement,
            ),
        })
        .expect("authorized confirmation should succeed");

    assert_eq!(confirmed.status(), MemoryStatus::Confirmed);
    assert_eq!(confirmed.version(), 2);
}

#[test]
fn another_subject_cannot_confirm_proposal() {
    let mut store = InMemoryStore::new();
    let mut service = MemoryProposalService::new(&mut store);
    service
        .propose(ProposeMemoryCommand {
            grant: grant(
                "principal_private",
                vec![WritePermission::ProposeMemory],
            ),
            memory_id: MemoryId::new("memory_01"),
            scope: MemoryScope::Global,
            kind: MemoryKind::Observation,
            content: "Private observation".to_owned(),
            evidence: evidence(
                "evidence_agent",
                EvidenceSource::AgentObservation,
            ),
        })
        .expect("authorized proposal should succeed");

    let error = service
        .confirm(ConfirmMemoryCommand {
            grant: grant(
                "principal_other",
                vec![WritePermission::ConfirmMemory],
            ),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            evidence: evidence(
                "evidence_other",
                EvidenceSource::UserStatement,
            ),
        })
        .expect_err("another subject must not confirm proposal");

    assert_eq!(error, ApplicationError::NotFound);
}

#[test]
fn client_without_proposal_permission_is_denied() {
    let mut store = InMemoryStore::new();
    let error = MemoryProposalService::new(&mut store)
        .propose(ProposeMemoryCommand {
            grant: grant("principal_01", Vec::new()),
            memory_id: MemoryId::new("memory_01"),
            scope: MemoryScope::Global,
            kind: MemoryKind::Observation,
            content: "Unauthorized observation".to_owned(),
            evidence: evidence(
                "evidence_agent",
                EvidenceSource::AgentObservation,
            ),
        })
        .expect_err("missing proposal permission should fail");

    assert_eq!(error, ApplicationError::AccessDenied);
}
