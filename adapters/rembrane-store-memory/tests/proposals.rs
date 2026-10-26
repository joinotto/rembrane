use rembrane_application::{
    ApplicationError, ConfirmMemoryCommand, EventRepository, MemoryProposalService,
    MemoryRepository, ProposeMemoryCommand,
};
use rembrane_domain::{
    ClientId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind,
    MemoryScope, MemoryStatus, PrincipalId, ReadScope, WorkspaceId, WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn grant(subject_id: &str, permissions: Vec<WritePermission>) -> WriteGrant {
    WriteGrant {
        client_id: ClientId::new("assistant_01"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new(subject_id),
        scopes: vec![ReadScope::Global],
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
            grant: grant("principal_01", vec![WritePermission::ProposeMemory]),
            memory_id: MemoryId::new("memory_01"),
            scope: MemoryScope::Global,
            kind: MemoryKind::Observation,
            content: "The user may prefer aisle seats.".to_owned(),
            evidence: evidence("evidence_agent", EvidenceSource::AgentObservation),
            event_id: EventId::new("event_01"),
            expected_previous_sequence: 0,
            projections: Vec::new(),
        })
        .expect("authorized proposal should succeed");

    assert_eq!(proposal.status(), MemoryStatus::Proposed);

    let confirmed = service
        .confirm(ConfirmMemoryCommand {
            grant: grant("principal_01", vec![WritePermission::ConfirmMemory]),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            evidence: evidence("evidence_user", EvidenceSource::UserStatement),
            event_id: EventId::new("event_02"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
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
            grant: grant("principal_private", vec![WritePermission::ProposeMemory]),
            memory_id: MemoryId::new("memory_01"),
            scope: MemoryScope::Global,
            kind: MemoryKind::Observation,
            content: "Private observation".to_owned(),
            evidence: evidence("evidence_agent", EvidenceSource::AgentObservation),
            event_id: EventId::new("event_01"),
            expected_previous_sequence: 0,
            projections: Vec::new(),
        })
        .expect("authorized proposal should succeed");

    let error = service
        .confirm(ConfirmMemoryCommand {
            grant: grant("principal_other", vec![WritePermission::ConfirmMemory]),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            evidence: evidence("evidence_other", EvidenceSource::UserStatement),
            event_id: EventId::new("event_02"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
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
            evidence: evidence("evidence_agent", EvidenceSource::AgentObservation),
            event_id: EventId::new("event_01"),
            expected_previous_sequence: 0,
            projections: Vec::new(),
        })
        .expect_err("missing proposal permission should fail");

    assert_eq!(error, ApplicationError::AccessDenied);
}

#[test]
fn denied_confirmation_preserves_proposal_evidence_and_event_stream() {
    let owner = grant("principal_01", vec![WritePermission::ConfirmMemory]);
    let mut no_permission = owner.clone();
    no_permission.permissions = vec![WritePermission::ProposeMemory];
    let mut wrong_scope = owner.clone();
    wrong_scope.scopes = vec![ReadScope::Domain {
        name: "travel".to_owned(),
    }];
    let mut wrong_subject = owner.clone();
    wrong_subject.subject_id = PrincipalId::new("principal_other");
    let mut wrong_workspace = owner.clone();
    wrong_workspace.workspace_id = WorkspaceId::new("workspace_other");
    for (approval_grant, expected_version, previous_sequence, expected_error) in [
        (no_permission, 1, 1, ApplicationError::AccessDenied),
        (wrong_scope, 1, 1, ApplicationError::AccessDenied),
        (wrong_subject, 1, 1, ApplicationError::NotFound),
        (wrong_workspace, 1, 1, ApplicationError::NotFound),
        (owner.clone(), 2, 1, ApplicationError::VersionConflict),
        (owner, 1, 2, ApplicationError::SequenceConflict),
    ] {
        let mut store = InMemoryStore::new();
        let proposal = MemoryProposalService::new(&mut store)
            .propose(ProposeMemoryCommand {
                grant: grant("principal_01", vec![WritePermission::ProposeMemory]),
                memory_id: MemoryId::new("memory_01"),
                scope: MemoryScope::Global,
                kind: MemoryKind::Observation,
                content: "Private observation".to_owned(),
                evidence: evidence("evidence_agent", EvidenceSource::AgentObservation),
                event_id: EventId::new("event_01"),
                expected_previous_sequence: 0,
                projections: Vec::new(),
            })
            .expect("valid proposal");
        let events_before = store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("proposal event");
        let error = MemoryProposalService::new(&mut store)
            .confirm(ConfirmMemoryCommand {
                grant: approval_grant,
                memory_id: MemoryId::new("memory_01"),
                expected_version,
                evidence: evidence("evidence_user", EvidenceSource::UserStatement),
                event_id: EventId::new("event_02"),
                expected_previous_sequence: previous_sequence,
                projections: Vec::new(),
            })
            .expect_err("denied confirmation");
        assert_eq!(error, expected_error);
        assert_eq!(
            store
                .find(
                    &WorkspaceId::new("workspace_01"),
                    &MemoryId::new("memory_01")
                )
                .expect("find proposal"),
            Some(proposal)
        );
        assert_eq!(
            store
                .list_events_since(&WorkspaceId::new("workspace_01"), 0)
                .expect("unchanged events"),
            events_before
        );
    }
}
