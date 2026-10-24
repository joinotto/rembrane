use std::collections::BTreeSet;

use rembrane_application::{
    ApplicationError, AuthorizeClientCommand, AuthorizeClientService, RemoteAccessAuthenticator,
    RemoteHttpAuthorization, RemoteTokenVerificationError, RemoteTokenVerifier,
    WorkspaceRepository,
};
use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
use rembrane_domain::{
    ClientId, Membership, Principal, PrincipalId, ReadScope, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;

struct FixtureVerifier;

impl RemoteTokenVerifier for FixtureVerifier {
    fn verify(
        &self,
        bearer_token: &str,
    ) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
        let (subject, workspace, audience, expiry) = match bearer_token {
            "token-alpha" => (
                "principal_alpha",
                "workspace_alpha",
                "https://memory.example.test/mcp",
                2_000,
            ),
            "token-cross-tenant" => (
                "principal_alpha",
                "workspace_beta",
                "https://memory.example.test/mcp",
                2_000,
            ),
            "token-wrong-audience" => (
                "principal_alpha",
                "workspace_alpha",
                "https://other.example.test/mcp",
                2_000,
            ),
            "token-expired" => (
                "principal_alpha",
                "workspace_alpha",
                "https://memory.example.test/mcp",
                1_000,
            ),
            _ => return Err(RemoteTokenVerificationError),
        };
        Ok(RemoteTokenClaims {
            issuer: "https://identity.example.test".to_owned(),
            audience: vec![audience.to_owned()],
            subject_id: PrincipalId::new(subject),
            client_id: ClientId::new("remote_client"),
            workspace_id: WorkspaceId::new(workspace),
            scopes: BTreeSet::from([RemoteAccessScope::ContextRead]),
            expires_at_epoch_seconds: expiry,
            not_before_epoch_seconds: None,
        })
    }
}

fn store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    for suffix in ["alpha", "beta"] {
        let principal_id = PrincipalId::new(format!("principal_{suffix}"));
        let workspace_id = WorkspaceId::new(format!("workspace_{suffix}"));
        store
            .initialize_personal_workspace(
                Principal::new(principal_id.clone()),
                Workspace::personal(workspace_id.clone()),
                Membership::new(workspace_id, principal_id, WorkspaceRole::Owner),
            )
            .expect("fixture workspace should initialize");
    }
    store
}

fn authenticate(token: &str) -> Result<rembrane_contracts::VerifiedRemoteAccess, ApplicationError> {
    static VERIFIER: FixtureVerifier = FixtureVerifier;
    let authenticator = RemoteAccessAuthenticator::new(
        &VERIFIER,
        "https://identity.example.test",
        "https://memory.example.test/mcp",
    );
    RemoteHttpAuthorization::new(&authenticator, &["https://app.example.test"]).authorize_tool(
        Some(&format!("Bearer {token}")),
        None,
        "rembrane_resolve_context",
        1_000,
    )
}

#[test]
fn verified_identity_must_still_hold_canonical_workspace_membership() {
    let store = store();
    let access = authenticate("token-alpha").expect("valid token should authenticate");
    let grants = AuthorizeClientService::new(&store)
        .execute(AuthorizeClientCommand {
            client_id: access.client_id().clone(),
            workspace_id: access.workspace_id().clone(),
            principal_id: access.subject_id().clone(),
            requested_read_scopes: vec![ReadScope::Global],
            requested_read_permissions: Vec::new(),
            requested_write_permissions: Vec::new(),
        })
        .expect("workspace owner should receive canonical authorization");

    assert_eq!(grants.read.workspace_id.as_str(), "workspace_alpha");
    assert_eq!(grants.read.subject_id.as_str(), "principal_alpha");
}

#[test]
fn cross_tenant_claim_pair_wrong_audience_and_expiry_fail_closed() {
    let store = store();
    let cross_tenant =
        authenticate("token-cross-tenant").expect("token claims are structurally valid");
    assert_eq!(
        AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id: cross_tenant.client_id().clone(),
                workspace_id: cross_tenant.workspace_id().clone(),
                principal_id: cross_tenant.subject_id().clone(),
                requested_read_scopes: vec![ReadScope::Global],
                requested_read_permissions: Vec::new(),
                requested_write_permissions: Vec::new(),
            })
            .expect_err("principal must not enter another tenant"),
        ApplicationError::AccessDenied
    );
    assert_eq!(
        authenticate("token-wrong-audience").expect_err("wrong audience must fail"),
        ApplicationError::AccessDenied
    );
    assert_eq!(
        authenticate("token-expired").expect_err("expiry boundary must fail"),
        ApplicationError::AccessDenied
    );
    assert_eq!(
        authenticate("unknown-token").expect_err("invalid token must fail"),
        ApplicationError::AccessDenied
    );
}
