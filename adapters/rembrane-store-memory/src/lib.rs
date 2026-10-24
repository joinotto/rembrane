//! Volatile reference adapter used by tests, examples, and local prototypes.

use rembrane_application::{
    ApplicationError, BookingResearchMutationRepository, BookingResearchRepository,
    CanonicalMutationRepository, CheckpointDisclosureRepository, CheckpointMutationRepository,
    CheckpointRepository, DisclosureRepository, EventRepository, InvitationRepository,
    MemberLifecycleRepository, MemberScopeGrantRepository, MembershipRepository, MemoryRepository,
    ProjectionOutboxRepository, ShareProposalMutationRepository, ShareProposalRepository,
    TravelDisclosureRepository, TripMutationRepository, TripRepository, WorkspaceRepository,
};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, BookingResearch, BookingResearchId, CanonicalEvent,
    CheckpointDisclosureReceipt, DisclosureReceipt, EntityId, EventPayload, Invitation,
    InvitationId, InvitationStatus, MemberScopeGrant, Membership, MemoryId, MemoryRecord,
    MemoryShareProposal, MemoryStatus, Principal, PrincipalId, ProjectionJob, ProjectionJobId,
    ProjectionOperation, ProjectionStatus, ProviderId, ShareProposalId, ShareProposalStatus,
    TravelDisclosureReceipt, Trip, Workspace, WorkspaceId, WorkspaceKind, WorkspaceRole,
};

#[derive(Debug, Default)]
pub struct InMemoryStore {
    principals: Vec<Principal>,
    workspaces: Vec<Workspace>,
    memories: Vec<MemoryRecord>,
    disclosures: Vec<DisclosureReceipt>,
    checkpoint_disclosures: Vec<CheckpointDisclosureReceipt>,
    travel_disclosures: Vec<TravelDisclosureReceipt>,
    events: Vec<CanonicalEvent>,
    checkpoints: Vec<ActivityCheckpoint>,
    invitations: Vec<Invitation>,
    member_scope_grants: Vec<MemberScopeGrant>,
    share_proposals: Vec<MemoryShareProposal>,
    memberships: Vec<Membership>,
    projections: Vec<ProjectionJob>,
    trips: Vec<Trip>,
    booking_research: Vec<BookingResearch>,
}

impl BookingResearchRepository for InMemoryStore {
    fn find_booking_research(
        &self,
        workspace_id: &WorkspaceId,
        research_id: &BookingResearchId,
    ) -> Result<Option<BookingResearch>, ApplicationError> {
        Ok(self
            .booking_research
            .iter()
            .find(|research| {
                research.workspace_id() == workspace_id && research.id() == research_id
            })
            .cloned())
    }

    fn list_booking_research_for_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Vec<BookingResearch>, ApplicationError> {
        Ok(self
            .booking_research
            .iter()
            .filter(|research| {
                research.workspace_id() == workspace_id && research.trip_id() == trip_id
            })
            .cloned()
            .collect())
    }
}

impl BookingResearchMutationRepository for InMemoryStore {
    fn insert_booking_research_with_event(
        &mut self,
        research: BookingResearch,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if self.booking_research.iter().any(|stored| {
            stored.workspace_id() == research.workspace_id() && stored.id() == research.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        let payload_matches = matches!(
            event.payload(),
            EventPayload::BookingResearchCaptured {
                research_id,
                trip_id,
                version,
            } if research_id == research.id()
                && trip_id == research.trip_id()
                && *version == research.version()
        );
        if event.workspace_id() != research.workspace_id()
            || event.subject_id() != Some(research.observed_by())
            || !payload_matches
        {
            return Err(ApplicationError::Validation(
                "event does not describe booking research capture".to_owned(),
            ));
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.booking_research.push(research);
        self.events.push(event);
        Ok(())
    }
}

impl TripRepository for InMemoryStore {
    fn find_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &rembrane_domain::EntityId,
    ) -> Result<Option<Trip>, ApplicationError> {
        Ok(self
            .trips
            .iter()
            .find(|trip| trip.workspace_id() == workspace_id && trip.id() == trip_id)
            .cloned())
    }

    fn list_trips_for_owner(
        &self,
        workspace_id: &WorkspaceId,
        owner_subject_id: &PrincipalId,
    ) -> Result<Vec<Trip>, ApplicationError> {
        Ok(self
            .trips
            .iter()
            .filter(|trip| {
                trip.workspace_id() == workspace_id && trip.owner_subject_id() == owner_subject_id
            })
            .cloned()
            .collect())
    }
}

impl TripMutationRepository for InMemoryStore {
    fn insert_trip_with_event(
        &mut self,
        trip: Trip,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_trip_event(&trip, &event, true)?;
        if self
            .trips
            .iter()
            .any(|stored| stored.workspace_id() == trip.workspace_id() && stored.id() == trip.id())
        {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.trips.push(trip);
        self.events.push(event);
        Ok(())
    }

    fn replace_trip_with_event(
        &mut self,
        trip: Trip,
        expected_trip_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_trip_event(&trip, &event, false)?;
        let position = self
            .trips
            .iter()
            .position(|stored| {
                stored.workspace_id() == trip.workspace_id() && stored.id() == trip.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.trips[position];
        if stored.owner_subject_id() != trip.owner_subject_id()
            || stored.version() != expected_trip_version
            || trip.version() != expected_trip_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.trips[position] = trip;
        self.events.push(event);
        Ok(())
    }
}

fn validate_trip_event(
    trip: &Trip,
    event: &CanonicalEvent,
    creating: bool,
) -> Result<(), ApplicationError> {
    let payload_matches = match event.payload() {
        EventPayload::TripCreated { trip_id, version } if creating => {
            trip_id == trip.id() && *version == trip.version()
        }
        EventPayload::TripRevised { trip_id, version } if !creating => {
            trip_id == trip.id() && *version == trip.version()
        }
        _ => false,
    };
    if event.workspace_id() != trip.workspace_id()
        || event.subject_id() != Some(trip.owner_subject_id())
        || !payload_matches
    {
        return Err(ApplicationError::Validation(
            "event does not describe canonical trip mutation".to_owned(),
        ));
    }
    Ok(())
}

impl WorkspaceRepository for InMemoryStore {
    fn initialize_personal_workspace(
        &mut self,
        principal: Principal,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        if workspace.kind() != WorkspaceKind::Personal
            || owner_membership.workspace_id() != workspace.id()
            || owner_membership.principal_id() != principal.id()
            || owner_membership.role() != WorkspaceRole::Owner
            || !owner_membership.is_active()
        {
            return Err(ApplicationError::Validation(
                "personal workspace bootstrap records must agree".to_owned(),
            ));
        }
        if self
            .principals
            .iter()
            .any(|stored| stored.id() == principal.id())
            || self
                .workspaces
                .iter()
                .any(|stored| stored.id() == workspace.id())
            || self.memberships.iter().any(|stored| {
                stored.workspace_id() == workspace.id() && stored.principal_id() == principal.id()
            })
        {
            return Err(ApplicationError::AlreadyExists);
        }

        self.principals.push(principal);
        self.workspaces.push(workspace);
        self.memberships.push(owner_membership);
        Ok(())
    }

    fn initialize_shared_workspace(
        &mut self,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        validate_shared_bootstrap(&workspace, &owner_membership)?;
        if !self
            .principals
            .iter()
            .any(|principal| principal.id() == owner_membership.principal_id())
        {
            return Err(ApplicationError::NotFound);
        }
        if self
            .workspaces
            .iter()
            .any(|stored| stored.id() == workspace.id())
            || self.memberships.iter().any(|stored| {
                stored.workspace_id() == workspace.id()
                    && stored.principal_id() == owner_membership.principal_id()
            })
        {
            return Err(ApplicationError::AlreadyExists);
        }
        self.workspaces.push(workspace);
        self.memberships.push(owner_membership);
        Ok(())
    }

    fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, ApplicationError> {
        Ok(self
            .principals
            .iter()
            .find(|principal| principal.id() == principal_id)
            .cloned())
    }

    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError> {
        Ok(self
            .workspaces
            .iter()
            .find(|workspace| workspace.id() == workspace_id)
            .cloned())
    }
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn disclosure_count(&self) -> usize {
        self.disclosures.len()
    }

    #[must_use]
    pub fn checkpoint_disclosure_count(&self) -> usize {
        self.checkpoint_disclosures.len()
    }

    #[must_use]
    pub fn travel_disclosures(&self) -> &[TravelDisclosureReceipt] {
        &self.travel_disclosures
    }
}

fn validate_shared_bootstrap(
    workspace: &Workspace,
    owner_membership: &Membership,
) -> Result<(), ApplicationError> {
    if workspace.kind() != WorkspaceKind::Shared
        || owner_membership.workspace_id() != workspace.id()
        || owner_membership.role() != WorkspaceRole::Owner
        || !owner_membership.is_active()
    {
        return Err(ApplicationError::Validation(
            "shared workspace bootstrap records must agree".to_owned(),
        ));
    }
    Ok(())
}

impl MemoryRepository for InMemoryStore {
    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .find(|memory| memory.workspace_id() == workspace_id && memory.id() == memory_id)
            .cloned())
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .filter(|memory| {
                memory.workspace_id() == workspace_id && memory.subject_id() == subject_id
            })
            .cloned()
            .collect())
    }
}

impl CanonicalMutationRepository for InMemoryStore {
    fn insert_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if memory.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "memory and event workspace must match".to_owned(),
            ));
        }
        if self.memories.iter().any(|stored| {
            stored.workspace_id() == memory.workspace_id() && stored.id() == memory.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.validate_projections(&memory, &projections)?;

        self.memories.push(memory);
        self.events.push(event);
        self.projections.extend(projections);
        Ok(())
    }

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if memory.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "memory and event workspace must match".to_owned(),
            ));
        }

        let position = self
            .memories
            .iter()
            .position(|stored| {
                stored.workspace_id() == memory.workspace_id() && stored.id() == memory.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.memories[position];
        if stored.version() != expected_memory_version
            || memory.version() != expected_memory_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.validate_projections(&memory, &projections)?;

        self.memories[position] = memory;
        self.events.push(event);
        self.projections.extend(projections);
        Ok(())
    }
}

impl DisclosureRepository for InMemoryStore {
    fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError> {
        let duplicate = self
            .disclosures
            .iter()
            .any(|stored| stored.id == receipt.id);

        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.disclosures.push(receipt);
        Ok(())
    }
}

impl CheckpointDisclosureRepository for InMemoryStore {
    fn append_checkpoint_disclosure(
        &mut self,
        receipt: CheckpointDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty() || receipt.checkpoint_version == 0 {
            return Err(ApplicationError::Validation(
                "invalid checkpoint disclosure".to_owned(),
            ));
        }
        if self
            .checkpoint_disclosures
            .iter()
            .any(|stored| stored.id == receipt.id)
        {
            return Err(ApplicationError::AlreadyExists);
        }
        let checkpoint_exists = self.checkpoints.iter().any(|checkpoint| {
            checkpoint.workspace_id() == &receipt.workspace_id
                && checkpoint.subject_id() == &receipt.subject_id
                && checkpoint.id() == &receipt.checkpoint_id
                && checkpoint.activity_id() == &receipt.activity_id
                && checkpoint.version() == receipt.checkpoint_version
        });
        if !checkpoint_exists {
            return Err(ApplicationError::VersionConflict);
        }
        self.checkpoint_disclosures.push(receipt);
        Ok(())
    }
}

impl TravelDisclosureRepository for InMemoryStore {
    fn append_travel_disclosure(
        &mut self,
        receipt: TravelDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty()
            || receipt.trip_version == 0
            || receipt.as_of.trim().is_empty()
            || receipt.research.iter().any(|item| item.version == 0)
        {
            return Err(ApplicationError::Validation(
                "invalid travel disclosure".to_owned(),
            ));
        }
        if self
            .travel_disclosures
            .iter()
            .any(|stored| stored.id == receipt.id)
        {
            return Err(ApplicationError::AlreadyExists);
        }
        let trip_exists = self.trips.iter().any(|trip| {
            trip.workspace_id() == &receipt.workspace_id
                && trip.id() == &receipt.trip_id
                && trip.owner_subject_id() == &receipt.subject_id
                && trip.version() == receipt.trip_version
        });
        let research_exists = receipt.research.iter().all(|disclosed| {
            self.booking_research.iter().any(|research| {
                research.workspace_id() == &receipt.workspace_id
                    && research.trip_id() == &receipt.trip_id
                    && research.id() == &disclosed.id
                    && research.version() == disclosed.version
            })
        });
        if !trip_exists || !research_exists {
            return Err(ApplicationError::VersionConflict);
        }
        self.travel_disclosures.push(receipt);
        Ok(())
    }
}

impl ProjectionOutboxRepository for InMemoryStore {
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError> {
        let duplicate = self.projections.iter().any(|stored| {
            stored.id() == job.id()
                || (stored.workspace_id() == job.workspace_id()
                    && stored.memory_id() == job.memory_id()
                    && stored.memory_version() == job.memory_version()
                    && stored.provider_id() == job.provider_id()
                    && stored.operation() == job.operation())
        });
        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.projections.push(job);
        Ok(())
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        Ok(self
            .projections
            .iter()
            .filter(|job| {
                job.provider_id() == provider_id && job.status() == ProjectionStatus::Pending
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .projections
            .iter_mut()
            .find(|stored| stored.id() == job.id())
            .ok_or(ApplicationError::NotFound)?;

        if stored.status() != expected_status || stored.attempts() != expected_attempts {
            return Err(ApplicationError::VersionConflict);
        }
        if stored.workspace_id() != job.workspace_id()
            || stored.memory_id() != job.memory_id()
            || stored.memory_version() != job.memory_version()
            || stored.provider_id() != job.provider_id()
            || stored.operation() != job.operation()
        {
            return Err(ApplicationError::Validation(
                "projection identity fields are immutable".to_owned(),
            ));
        }

        *stored = job;
        Ok(())
    }

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        Ok(self
            .projections
            .iter()
            .find(|job| job.workspace_id() == workspace_id && job.id() == job_id)
            .cloned())
    }
}

impl MembershipRepository for InMemoryStore {
    fn insert_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        let duplicate = self.memberships.iter().any(|stored| {
            stored.workspace_id() == membership.workspace_id()
                && stored.principal_id() == membership.principal_id()
        });
        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.memberships.push(membership);
        Ok(())
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        Ok(self
            .memberships
            .iter()
            .find(|membership| {
                membership.workspace_id() == workspace_id
                    && membership.principal_id() == principal_id
            })
            .cloned())
    }

    fn replace_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        let stored = self
            .memberships
            .iter_mut()
            .find(|stored| {
                stored.workspace_id() == membership.workspace_id()
                    && stored.principal_id() == membership.principal_id()
            })
            .ok_or(ApplicationError::NotFound)?;

        *stored = membership;
        Ok(())
    }
}

impl InvitationRepository for InMemoryStore {
    fn insert_invitation(&mut self, invitation: Invitation) -> Result<(), ApplicationError> {
        if self.invitations.iter().any(|stored| {
            stored.id() == invitation.id()
                || (stored.workspace_id() == invitation.workspace_id()
                    && stored.invited_principal_id() == invitation.invited_principal_id()
                    && stored.status() == InvitationStatus::Pending)
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.invitations.push(invitation);
        Ok(())
    }

    fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, ApplicationError> {
        Ok(self
            .invitations
            .iter()
            .find(|invitation| {
                invitation.workspace_id() == workspace_id && invitation.id() == invitation_id
            })
            .cloned())
    }

    fn accept_invitation_with_membership(
        &mut self,
        invitation: Invitation,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
        if invitation.status() != InvitationStatus::Accepted
            || invitation.workspace_id() != membership.workspace_id()
            || invitation.invited_principal_id() != membership.principal_id()
            || invitation.role() != membership.role()
        {
            return Err(ApplicationError::Validation(
                "accepted invitation and membership must agree".to_owned(),
            ));
        }
        let invitation_position = self
            .invitations
            .iter()
            .position(|stored| {
                stored.workspace_id() == invitation.workspace_id()
                    && stored.id() == invitation.id()
                    && stored.status() == InvitationStatus::Pending
            })
            .ok_or(ApplicationError::VersionConflict)?;
        if self.memberships.iter().any(|stored| {
            stored.workspace_id() == membership.workspace_id()
                && stored.principal_id() == membership.principal_id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }

        self.invitations[invitation_position] = invitation;
        self.memberships.push(membership);
        Ok(())
    }

    fn replace_invitation(
        &mut self,
        invitation: Invitation,
        expected_status: InvitationStatus,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .invitations
            .iter_mut()
            .find(|stored| {
                stored.workspace_id() == invitation.workspace_id() && stored.id() == invitation.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        if stored.status() != expected_status
            || stored.invited_principal_id() != invitation.invited_principal_id()
            || stored.invited_by() != invitation.invited_by()
            || stored.role() != invitation.role()
        {
            return Err(ApplicationError::VersionConflict);
        }
        *stored = invitation;
        Ok(())
    }
}

impl ShareProposalRepository for InMemoryStore {
    fn insert_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
    ) -> Result<(), ApplicationError> {
        self.validate_share_proposal_insert(&proposal)?;
        self.share_proposals.push(proposal);
        Ok(())
    }

    fn find_share_proposal(
        &self,
        source_workspace_id: &WorkspaceId,
        proposal_id: &ShareProposalId,
    ) -> Result<Option<MemoryShareProposal>, ApplicationError> {
        Ok(self
            .share_proposals
            .iter()
            .find(|proposal| {
                proposal.source_workspace_id() == source_workspace_id
                    && proposal.id() == proposal_id
            })
            .cloned())
    }

    fn list_share_proposals_for_source(
        &self,
        source_workspace_id: &WorkspaceId,
        source_subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryShareProposal>, ApplicationError> {
        Ok(self
            .share_proposals
            .iter()
            .filter(|proposal| {
                proposal.source_workspace_id() == source_workspace_id
                    && proposal.source_subject_id() == source_subject_id
            })
            .cloned()
            .collect())
    }

    fn replace_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .share_proposals
            .iter_mut()
            .find(|stored| {
                stored.source_workspace_id() == proposal.source_workspace_id()
                    && stored.id() == proposal.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        if stored.status() != expected_status
            || stored.source_memory_id() != proposal.source_memory_id()
            || stored.source_memory_version() != proposal.source_memory_version()
            || stored.source_subject_id() != proposal.source_subject_id()
            || stored.target_workspace_id() != proposal.target_workspace_id()
            || stored.target_scope() != proposal.target_scope()
            || stored.proposed_by() != proposal.proposed_by()
        {
            return Err(ApplicationError::VersionConflict);
        }
        *stored = proposal;
        Ok(())
    }
}

impl ShareProposalMutationRepository for InMemoryStore {
    fn insert_share_proposal_with_event(
        &mut self,
        proposal: MemoryShareProposal,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        self.validate_share_proposal_insert(&proposal)?;
        validate_share_proposed_event(&proposal, &event)?;
        self.validate_event(&event, expected_previous_sequence)?;

        self.share_proposals.push(proposal);
        self.events.push(event);
        Ok(())
    }

    fn approve_share_proposal_with_copy(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
        target_memory: MemoryRecord,
        source_event: CanonicalEvent,
        target_event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_source_sequence: u64,
        expected_target_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let position = self
            .share_proposals
            .iter()
            .position(|stored| {
                stored.source_workspace_id() == proposal.source_workspace_id()
                    && stored.id() == proposal.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.share_proposals[position];
        if stored.status() != expected_status
            || proposal.status() != ShareProposalStatus::Approved
            || !same_share_proposal_identity(stored, &proposal)
        {
            return Err(ApplicationError::VersionConflict);
        }
        let source = self
            .memories
            .iter()
            .find(|memory| {
                memory.workspace_id() == proposal.source_workspace_id()
                    && memory.id() == proposal.source_memory_id()
            })
            .ok_or(ApplicationError::NotFound)?;
        if source.version() != proposal.source_memory_version()
            || source.subject_id() != proposal.source_subject_id()
            || source.status() != MemoryStatus::Confirmed
        {
            return Err(ApplicationError::VersionConflict);
        }
        validate_shared_copy(&proposal, source, &target_memory)?;
        validate_share_approval_events(&proposal, &target_memory, &source_event, &target_event)?;
        if self.memories.iter().any(|memory| {
            memory.workspace_id() == target_memory.workspace_id()
                && memory.id() == target_memory.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&source_event, expected_source_sequence)?;
        self.validate_event(&target_event, expected_target_sequence)?;
        if source_event.id() == target_event.id() {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_projections(&target_memory, &projections)?;

        self.share_proposals[position] = proposal;
        self.memories.push(target_memory);
        self.events.push(source_event);
        self.events.push(target_event);
        self.projections.extend(projections);
        Ok(())
    }
}

impl MemberScopeGrantRepository for InMemoryStore {
    fn insert_member_scope_grant(
        &mut self,
        grant: MemberScopeGrant,
    ) -> Result<(), ApplicationError> {
        if self.member_scope_grants.iter().any(|stored| {
            stored.workspace_id() == grant.workspace_id()
                && stored.principal_id() == grant.principal_id()
                && stored.scope() == grant.scope()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.member_scope_grants.push(grant);
        Ok(())
    }

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError> {
        Ok(self
            .member_scope_grants
            .iter()
            .filter(|grant| {
                grant.workspace_id() == workspace_id && grant.principal_id() == principal_id
            })
            .cloned()
            .collect())
    }

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
    ) -> Result<(), ApplicationError> {
        let position = self
            .member_scope_grants
            .iter()
            .position(|stored| stored == grant)
            .ok_or(ApplicationError::NotFound)?;
        self.member_scope_grants.remove(position);
        Ok(())
    }
}

impl MemberLifecycleRepository for InMemoryStore {
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: rembrane_domain::MembershipStatus,
    ) -> Result<(), ApplicationError> {
        if membership.status() != rembrane_domain::MembershipStatus::Removed {
            return Err(ApplicationError::Validation(
                "member lifecycle transition must end in removed status".to_owned(),
            ));
        }
        let stored = self
            .memberships
            .iter_mut()
            .find(|stored| {
                stored.workspace_id() == membership.workspace_id()
                    && stored.principal_id() == membership.principal_id()
            })
            .ok_or(ApplicationError::NotFound)?;
        if stored.status() != expected_status || stored.role() != membership.role() {
            return Err(ApplicationError::VersionConflict);
        }
        *stored = membership.clone();
        self.member_scope_grants.retain(|grant| {
            grant.workspace_id() != membership.workspace_id()
                || grant.principal_id() != membership.principal_id()
        });
        Ok(())
    }
}

impl CheckpointRepository for InMemoryStore {
    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        Ok(self
            .checkpoints
            .iter()
            .filter(|checkpoint| {
                checkpoint.workspace_id() == workspace_id
                    && checkpoint.subject_id() == subject_id
                    && checkpoint.activity_id() == activity_id
            })
            .max_by_key(|checkpoint| checkpoint.version())
            .cloned())
    }

    fn list_checkpoints_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<ActivityCheckpoint>, ApplicationError> {
        Ok(self
            .checkpoints
            .iter()
            .filter(|checkpoint| {
                checkpoint.workspace_id() == workspace_id && checkpoint.subject_id() == subject_id
            })
            .cloned()
            .collect())
    }
}

impl CheckpointMutationRepository for InMemoryStore {
    fn insert_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if checkpoint.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "checkpoint and event workspace must match".to_owned(),
            ));
        }
        if self.checkpoints.iter().any(|stored| {
            stored.workspace_id() == checkpoint.workspace_id() && stored.id() == checkpoint.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&event, expected_previous_sequence)?;

        self.checkpoints.push(checkpoint);
        self.events.push(event);
        Ok(())
    }

    fn replace_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_checkpoint_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if checkpoint.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "checkpoint and event workspace must match".to_owned(),
            ));
        }
        let position = self
            .checkpoints
            .iter()
            .position(|stored| {
                stored.workspace_id() == checkpoint.workspace_id() && stored.id() == checkpoint.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.checkpoints[position];
        if stored.version() != expected_checkpoint_version
            || checkpoint.version() != expected_checkpoint_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_event(&event, expected_previous_sequence)?;

        self.checkpoints[position] = checkpoint;
        self.events.push(event);
        Ok(())
    }
}

impl EventRepository for InMemoryStore {
    fn append_event(
        &mut self,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let current_sequence = self
            .events
            .iter()
            .filter(|stored| stored.workspace_id() == event.workspace_id())
            .map(CanonicalEvent::sequence)
            .max()
            .unwrap_or(0);

        if current_sequence != expected_previous_sequence
            || event.sequence() != expected_previous_sequence.saturating_add(1)
        {
            return Err(ApplicationError::SequenceConflict);
        }

        let duplicate_id = self.events.iter().any(|stored| stored.id() == event.id());
        if duplicate_id {
            return Err(ApplicationError::AlreadyExists);
        }

        self.events.push(event);
        Ok(())
    }

    fn list_events_since(
        &self,
        workspace_id: &WorkspaceId,
        sequence: u64,
    ) -> Result<Vec<CanonicalEvent>, ApplicationError> {
        let mut events: Vec<_> = self
            .events
            .iter()
            .filter(|event| event.workspace_id() == workspace_id && event.sequence() > sequence)
            .cloned()
            .collect();
        events.sort_by_key(CanonicalEvent::sequence);
        Ok(events)
    }
}

impl InMemoryStore {
    fn validate_share_proposal_insert(
        &self,
        proposal: &MemoryShareProposal,
    ) -> Result<(), ApplicationError> {
        if proposal.status() != ShareProposalStatus::Pending {
            return Err(ApplicationError::Validation(
                "new share proposal must be pending".to_owned(),
            ));
        }
        if self.share_proposals.iter().any(|stored| {
            stored.source_workspace_id() == proposal.source_workspace_id()
                && stored.id() == proposal.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        let source = self
            .memories
            .iter()
            .find(|memory| {
                memory.workspace_id() == proposal.source_workspace_id()
                    && memory.id() == proposal.source_memory_id()
            })
            .ok_or(ApplicationError::NotFound)?;
        if source.version() != proposal.source_memory_version()
            || source.subject_id() != proposal.source_subject_id()
            || source.status() != MemoryStatus::Confirmed
        {
            return Err(ApplicationError::VersionConflict);
        }
        if !self.workspaces.iter().any(|workspace| {
            workspace.id() == proposal.source_workspace_id()
                && workspace.kind() == WorkspaceKind::Personal
        }) || !self.workspaces.iter().any(|workspace| {
            workspace.id() == proposal.target_workspace_id()
                && workspace.kind() == WorkspaceKind::Shared
        }) || !self
            .principals
            .iter()
            .any(|principal| principal.id() == proposal.proposed_by())
        {
            return Err(ApplicationError::NotFound);
        }
        Ok(())
    }

    fn validate_event(
        &self,
        event: &CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let current_sequence = self
            .events
            .iter()
            .filter(|stored| stored.workspace_id() == event.workspace_id())
            .map(CanonicalEvent::sequence)
            .max()
            .unwrap_or(0);
        if current_sequence != expected_previous_sequence
            || event.sequence() != expected_previous_sequence.saturating_add(1)
        {
            return Err(ApplicationError::SequenceConflict);
        }
        if self.events.iter().any(|stored| stored.id() == event.id()) {
            return Err(ApplicationError::AlreadyExists);
        }
        Ok(())
    }

    fn validate_projections(
        &self,
        memory: &MemoryRecord,
        projections: &[ProjectionJob],
    ) -> Result<(), ApplicationError> {
        let expected_operation = if memory.status() == rembrane_domain::MemoryStatus::Deleted {
            ProjectionOperation::Delete
        } else {
            ProjectionOperation::Upsert
        };

        for (index, projection) in projections.iter().enumerate() {
            if projection.workspace_id() != memory.workspace_id()
                || projection.memory_id() != memory.id()
                || projection.memory_version() != memory.version()
                || projection.operation() != expected_operation
            {
                return Err(ApplicationError::Validation(
                    "projection does not match canonical memory mutation".to_owned(),
                ));
            }
            if self.projections.iter().any(|stored| {
                stored.id() == projection.id()
                    || (stored.workspace_id() == projection.workspace_id()
                        && stored.memory_id() == projection.memory_id()
                        && stored.memory_version() == projection.memory_version()
                        && stored.provider_id() == projection.provider_id()
                        && stored.operation() == projection.operation())
            }) {
                return Err(ApplicationError::AlreadyExists);
            }
            if projections[..index].iter().any(|earlier| {
                earlier.id() == projection.id()
                    || (earlier.provider_id() == projection.provider_id()
                        && earlier.operation() == projection.operation())
            }) {
                return Err(ApplicationError::AlreadyExists);
            }
        }

        Ok(())
    }
}

fn same_share_proposal_identity(left: &MemoryShareProposal, right: &MemoryShareProposal) -> bool {
    left.source_workspace_id() == right.source_workspace_id()
        && left.id() == right.id()
        && left.source_memory_id() == right.source_memory_id()
        && left.source_memory_version() == right.source_memory_version()
        && left.source_subject_id() == right.source_subject_id()
        && left.target_workspace_id() == right.target_workspace_id()
        && left.target_scope() == right.target_scope()
        && left.proposed_by() == right.proposed_by()
}

fn validate_share_proposed_event(
    proposal: &MemoryShareProposal,
    event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    let valid_payload = matches!(
        event.payload(),
        EventPayload::MemoryShareProposed {
            proposal_id,
            source_memory_id,
            source_version,
            target_workspace_id,
        } if proposal_id == proposal.id()
            && source_memory_id == proposal.source_memory_id()
            && *source_version == proposal.source_memory_version()
            && target_workspace_id == proposal.target_workspace_id()
    );
    if proposal.status() != ShareProposalStatus::Pending
        || event.workspace_id() != proposal.source_workspace_id()
        || event.actor_id() != proposal.proposed_by()
        || event.subject_id() != Some(proposal.source_subject_id())
        || !valid_payload
    {
        return Err(ApplicationError::Validation(
            "event does not describe share proposal creation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_shared_copy(
    proposal: &MemoryShareProposal,
    source: &MemoryRecord,
    target: &MemoryRecord,
) -> Result<(), ApplicationError> {
    let evidence_preserved = target.evidence().len() == source.evidence().len().saturating_add(1)
        && target.evidence().starts_with(source.evidence());
    if target.workspace_id() != proposal.target_workspace_id()
        || target.subject_id() != proposal.source_subject_id()
        || target.scope() != proposal.target_scope()
        || target.kind() != source.kind()
        || target.status() != MemoryStatus::Confirmed
        || target.version() != 1
        || target.content() != source.content()
        || !evidence_preserved
    {
        return Err(ApplicationError::Validation(
            "target memory is not an approved copy of the exact source".to_owned(),
        ));
    }
    Ok(())
}

fn validate_share_approval_events(
    proposal: &MemoryShareProposal,
    target: &MemoryRecord,
    source_event: &CanonicalEvent,
    target_event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    let source_payload = matches!(
        source_event.payload(),
        EventPayload::MemoryShareApproved {
            proposal_id,
            target_workspace_id,
            target_memory_id,
        } if proposal_id == proposal.id()
            && target_workspace_id == proposal.target_workspace_id()
            && target_memory_id == target.id()
    );
    let target_payload = matches!(
        target_event.payload(),
        EventPayload::MemorySharedIn {
            proposal_id,
            source_workspace_id,
            source_memory_id,
            source_version,
            target_memory_id,
            target_version,
        } if proposal_id == proposal.id()
            && source_workspace_id == proposal.source_workspace_id()
            && source_memory_id == proposal.source_memory_id()
            && *source_version == proposal.source_memory_version()
            && target_memory_id == target.id()
            && *target_version == target.version()
    );
    if source_event.workspace_id() != proposal.source_workspace_id()
        || target_event.workspace_id() != proposal.target_workspace_id()
        || source_event.actor_id() != proposal.source_subject_id()
        || target_event.actor_id() != proposal.source_subject_id()
        || source_event.subject_id() != Some(proposal.source_subject_id())
        || target_event.subject_id() != Some(proposal.source_subject_id())
        || !source_payload
        || !target_payload
    {
        return Err(ApplicationError::Validation(
            "events do not describe atomic share approval".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_application::{
        ApplicationError, CanonicalMutationRepository, EventRepository, MemoryRepository,
    };
    use rembrane_domain::{
        CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource,
        MemoryId, MemoryRecord, MemoryScope, PrincipalId, WorkspaceId,
    };

    use super::InMemoryStore;

    fn preference(
        memory_id: &str,
        workspace_id: &str,
        subject_id: &str,
        content: &str,
    ) -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new(memory_id),
            WorkspaceId::new(workspace_id),
            PrincipalId::new(subject_id),
            MemoryScope::Global,
            content,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{memory_id}")),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("test preference should be valid")
    }

    fn insert(
        store: &mut InMemoryStore,
        memory: MemoryRecord,
        event_id: &str,
    ) -> Result<(), ApplicationError> {
        let event = CanonicalEvent::new(
            EventId::new(event_id),
            memory.workspace_id().clone(),
            memory.subject_id().clone(),
            Some(memory.subject_id().clone()),
            1,
            EventPayload::MemoryCreated {
                memory_id: memory.id().clone(),
                version: memory.version(),
            },
        )
        .expect("test event should be valid");
        store.insert_memory_with_event(memory, event, Vec::new(), 0)
    }

    #[test]
    fn does_not_find_memory_across_workspace_boundary() {
        let mut store = InMemoryStore::new();
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_private",
                "principal_01",
                "Call me Hippo",
            ),
            "event_private",
        )
        .expect("insert should succeed");

        let result = store
            .find(
                &WorkspaceId::new("workspace_other"),
                &MemoryId::new("memory_01"),
            )
            .expect("lookup should succeed");

        assert!(result.is_none());
    }

    #[test]
    fn permits_same_memory_id_in_different_workspaces() {
        let mut store = InMemoryStore::new();
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_one",
                "principal_01",
                "Preference one",
            ),
            "event_one",
        )
        .expect("first insert should succeed");
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_two",
                "principal_02",
                "Preference two",
            ),
            "event_two",
        )
        .expect("second workspace insert should succeed");

        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_one"),
                    &PrincipalId::new("principal_01"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_two"),
                    &PrincipalId::new("principal_02"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_memory_within_workspace() {
        let mut store = InMemoryStore::new();
        let memory = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );

        insert(&mut store, memory.clone(), "event_01").expect("first insert should succeed");
        let error =
            insert(&mut store, memory, "event_02").expect_err("duplicate insert should fail");

        assert_eq!(error, ApplicationError::AlreadyExists);
    }

    #[test]
    fn rejects_stale_revision() {
        let mut store = InMemoryStore::new();
        let original = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );
        insert(&mut store, original.clone(), "event_01").expect("initial insert should succeed");

        let revised = original
            .revise(
                "Call me Captain Hippo",
                rembrane_domain::EvidenceReference::new(
                    rembrane_domain::EvidenceId::new("evidence_revision"),
                    rembrane_domain::EvidenceSource::UserStatement,
                ),
            )
            .expect("revision should be valid");

        let revision_event = CanonicalEvent::new(
            EventId::new("event_02"),
            WorkspaceId::new("workspace_one"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            2,
            EventPayload::MemoryRevised {
                memory_id: MemoryId::new("memory_01"),
                version: 2,
            },
        )
        .expect("test event should be valid");
        let error = store
            .replace_memory_with_event(revised, 2, revision_event, Vec::new(), 1)
            .expect_err("stale expected version should fail");

        assert_eq!(error, ApplicationError::VersionConflict);
    }

    fn event(id: &str, workspace_id: &str, sequence: u64) -> CanonicalEvent {
        CanonicalEvent::new(
            EventId::new(id),
            WorkspaceId::new(workspace_id),
            PrincipalId::new("principal_01"),
            None,
            sequence,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_01"),
                version: 1,
            },
        )
        .expect("test event should be valid")
    }

    #[test]
    fn enforces_workspace_event_sequence() {
        let mut store = InMemoryStore::new();
        store
            .append_event(event("event_01", "workspace_01", 1), 0)
            .expect("first event should append");

        let error = store
            .append_event(event("event_03", "workspace_01", 3), 1)
            .expect_err("sequence gap should fail");

        assert_eq!(error, ApplicationError::SequenceConflict);
    }

    #[test]
    fn keeps_event_sequences_independent_between_workspaces() {
        let mut store = InMemoryStore::new();
        store
            .append_event(event("event_one", "workspace_one", 1), 0)
            .expect("first workspace event should append");
        store
            .append_event(event("event_two", "workspace_two", 1), 0)
            .expect("second workspace event should append");

        assert_eq!(
            store
                .list_events_since(&WorkspaceId::new("workspace_one"), 0)
                .expect("event listing should succeed")
                .len(),
            1
        );
    }
}
