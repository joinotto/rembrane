export interface RembraneClientOptions {
  baseUrl: string;
  token: string;
  fetch: typeof globalThis.fetch;
  maximumResponseBytes?: number;
}

export type ChannelProcessorChannel =
  | "whatsapp-business"
  | "imessage-extension"
  | "mobile-share";

export interface ChannelProcessorMessage {
  protocolVersion: "0.1";
  channel: ChannelProcessorChannel;
  eventId: string;
  workspaceId: string;
  principalId: string;
  clientId: string;
  text: string;
  receivedAtEpochSeconds: number;
}

export type ChannelProcessorStatus = "processed" | "duplicate";

export interface ChannelProcessorAcknowledgement {
  protocolVersion: "0.1";
  eventId: string;
  status: ChannelProcessorStatus;
}

export function parseChannelProcessorMessage(
  value: unknown,
): Readonly<ChannelProcessorMessage>;

export function createChannelProcessorAcknowledgement(
  eventId: string,
  status: ChannelProcessorStatus,
): Readonly<ChannelProcessorAcknowledgement>;

export interface WorkspaceRequest {
  workspaceId: string;
}

export type GraphDirection = "incoming" | "outgoing" | "both";

export interface ResolveGraphContextRequest extends WorkspaceRequest {
  subjectId: string;
  nodeId: string;
  direction: GraphDirection;
  validAtEpochSeconds: number;
  maximumCandidates?: number;
  purpose: string;
  domain?: string | null;
  entityId?: string | null;
  activityId?: string | null;
}

export interface GraphEdge {
  edgeId: string;
  sourceNodeId: string;
  targetNodeId: string;
  relation: string;
  version: number;
  validFromEpochSeconds: number;
  validUntilEpochSeconds: number | null;
  recordedAtEpochSeconds: number;
}

export interface ResolveGraphContextResponse {
  disclosureId: string;
  edges: GraphEdge[];
}

export interface CheckpointActivityRequest extends WorkspaceRequest {
  subjectId: string;
  entityId?: string | null;
  goal?: string | null;
  summary: string;
  nextSteps?: string[];
  blockers?: string[];
  stateFingerprint?: string | null;
  expectedVersion?: number | null;
  expectedPreviousSequence: number;
}

export interface ResumeActivityQuery extends WorkspaceRequest {
  subjectId: string;
  purpose?: string;
  stateFingerprint?: string;
}

export interface ActivityCheckpoint {
  checkpointId: string;
  workspaceId: string;
  subjectId: string;
  activityId: string;
  entityId: string | null;
  goal: string;
  summary: string;
  nextSteps: string[];
  blockers: string[];
  stateFingerprint: string | null;
  version: number;
  stale?: boolean;
  disclosureId?: string;
}

export interface MemoryScopeRequest extends WorkspaceRequest {
  subjectId: string;
  domain?: string | null;
  entityId?: string | null;
  activityId?: string | null;
  expectedPreviousSequence: number;
}

export interface RememberPreferenceRequest extends MemoryScopeRequest {
  content: string;
}

export interface CorrectMemoryRequest extends MemoryScopeRequest {
  replacement: string;
  expectedVersion: number;
}

export interface DeleteMemoryRequest extends MemoryScopeRequest {
  reason: string;
  expectedVersion: number;
}

export interface MemoryMutation {
  memoryId: string;
  version: number;
  status: "confirmed" | "deleted";
}

export type WorkspaceInvitationRole = "admin" | "member" | "viewer";
export type WorkspaceInvitationStatus = "pending" | "accepted" | "revoked" | "expired";

export interface CreateWorkspaceInvitationRequest extends WorkspaceRequest {
  invitationId: string;
  invitedPrincipalId: string;
  role: WorkspaceInvitationRole;
  ttlSeconds: number;
  requestId: string;
}

export interface WorkspaceInvitationTransitionRequest extends WorkspaceRequest {
  invitationId: string;
  requestId: string;
}

export interface WorkspaceInvitation {
  workspaceId: string;
  invitationId: string;
  invitedPrincipalId: string;
  role: WorkspaceInvitationRole;
  status: WorkspaceInvitationStatus;
  expiresAtEpochSeconds: number;
}

export interface WorkspaceInvitationListItem extends WorkspaceInvitation {
  invitedBy: string;
  createdAtEpochSeconds: number;
}

export interface WorkspaceInvitationListQuery extends WorkspaceRequest {
  status?: WorkspaceInvitationStatus;
  limit?: number;
}

export interface WorkspaceInvitationList {
  workspaceId: string;
  invitations: WorkspaceInvitationListItem[];
}

export interface AuditQuery extends WorkspaceRequest {
  afterEpochSeconds?: number;
  limit?: number;
}

export interface LegalHoldRequest extends WorkspaceRequest {
  holdId: string;
  requestId: string;
}

export interface RetentionPolicyRequest extends WorkspaceRequest {
  expectedVersion?: number | null;
  userMemoryDays?: number | null;
  activityCheckpointDays?: number | null;
  travelResearchDays?: number | null;
  disclosureReceiptDays?: number | null;
  canonicalEventDays?: number | null;
  administrativeAuditDays?: number | null;
  requestId: string;
}

export interface RetentionPurgeRequest extends WorkspaceRequest {
  maximumItems: number;
}

export class RembraneError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string);
}

export class RembraneClient {
  constructor(options: RembraneClientOptions);
  resolveContext<T = unknown>(request: unknown): Promise<T>;
  resolveGraphContext(
    request: ResolveGraphContextRequest,
  ): Promise<ResolveGraphContextResponse>;
  rememberPreference(request: RememberPreferenceRequest): Promise<MemoryMutation>;
  correctMemory(
    memoryId: string,
    request: CorrectMemoryRequest,
  ): Promise<MemoryMutation>;
  deleteMemory(
    memoryId: string,
    request: DeleteMemoryRequest,
  ): Promise<MemoryMutation>;
  checkpointActivity(
    activityId: string,
    request: CheckpointActivityRequest,
  ): Promise<ActivityCheckpoint>;
  resumeActivity(
    activityId: string,
    query: ResumeActivityQuery,
  ): Promise<ActivityCheckpoint>;
  rotateWorkspaceKey<T = unknown>(request: WorkspaceRequest): Promise<T>;
  createWorkspaceInvitation(
    request: CreateWorkspaceInvitationRequest,
  ): Promise<WorkspaceInvitation>;
  acceptWorkspaceInvitation(
    request: WorkspaceInvitationTransitionRequest,
  ): Promise<WorkspaceInvitation>;
  revokeWorkspaceInvitation(
    request: WorkspaceInvitationTransitionRequest,
  ): Promise<WorkspaceInvitation>;
  listWorkspaceInvitations(
    query: WorkspaceInvitationListQuery,
  ): Promise<WorkspaceInvitationList>;
  listAdministrativeAudit<T = unknown>(query: AuditQuery): Promise<T>;
  setRetentionPolicy<T = unknown>(request: RetentionPolicyRequest): Promise<T>;
  placeLegalHold<T = unknown>(request: LegalHoldRequest): Promise<T>;
  releaseLegalHold<T = unknown>(request: LegalHoldRequest): Promise<T>;
  executeRetentionPurge<T = unknown>(request: RetentionPurgeRequest): Promise<T>;
}
