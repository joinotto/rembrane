export interface RembraneClientOptions {
  baseUrl: string;
  token: string;
  fetch: typeof globalThis.fetch;
  maximumResponseBytes?: number;
}

export interface WorkspaceRequest {
  workspaceId: string;
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
  listAdministrativeAudit<T = unknown>(query: AuditQuery): Promise<T>;
  setRetentionPolicy<T = unknown>(request: RetentionPolicyRequest): Promise<T>;
  placeLegalHold<T = unknown>(request: LegalHoldRequest): Promise<T>;
  releaseLegalHold<T = unknown>(request: LegalHoldRequest): Promise<T>;
  executeRetentionPurge<T = unknown>(request: RetentionPurgeRequest): Promise<T>;
}
