import Foundation
import Rembrane

private actor MockTransport: RembraneTransport {
    private(set) var request: URLRequest?

    func send(
        _ request: URLRequest,
        maximumResponseBytes: Int
    ) async throws -> RembraneHTTPResponse {
        self.request = request
        let body: Data
        if request.url?.path.hasSuffix("/administrative-audit") == true {
            body = Data(#"{"events":[]}"#.utf8)
        } else if request.httpMethod == "GET" {
            body = Data(#"{"workspaceId":"team/name","invitations":[]}"#.utf8)
        } else {
            body = Data(#"{"status":"pending"}"#.utf8)
        }
        return RembraneHTTPResponse(
            status: 200,
            headers: ["content-type": "application/json"],
            body: body
        )
    }
}

private struct AuditResponse: Decodable {
    let events: [String]
}

private struct InvitationRequest: Encodable {
    let workspaceId: String
    let invitationId: String
    let invitedPrincipalId: String?
    let role: String?
    let ttlSeconds: UInt64?
    let requestId: String
}

private struct InvitationResponse: Decodable {
    let status: String
}

private struct InvitationListResponse: Decodable {
    let workspaceId: String
    let invitations: [String]
}

private struct MockShareSigner: RembraneMobileShareSigner {
    func signatureHeader(for body: Data) throws -> String {
        precondition(!body.isEmpty)
        return "sha256=" + String(repeating: "a", count: 64)
    }
}

@main
private struct RembraneSmoke {
    static func main() async throws {
        let transport = MockTransport()
        let client = try RembraneClient(
            baseURL: URL(string: "http://127.0.0.1:8787/v1")!,
            token: "test-token",
            transport: transport
        )
        let response: AuditResponse = try await client.listAdministrativeAudit(
            workspaceID: "team",
            afterEpochSeconds: 10,
            limit: 20
        )
        precondition(response.events.isEmpty)
        let request = await transport.request
        precondition(
            request?.value(forHTTPHeaderField: "Authorization") == "Bearer test-token"
        )
        precondition(
            request?.url?.absoluteString
                == "http://127.0.0.1:8787/v1/administrative-audit?workspaceId=team&afterEpochSeconds=10&limit=20"
        )

        let createRequest = InvitationRequest(
            workspaceId: "team",
            invitationId: "invite-1",
            invitedPrincipalId: "principal-2",
            role: "member",
            ttlSeconds: 3_600,
            requestId: "request-1"
        )
        let created: InvitationResponse = try await client.createWorkspaceInvitation(
            createRequest
        )
        precondition(created.status == "pending")
        var invitationRequest = await transport.request
        precondition(invitationRequest?.httpMethod == "POST")
        precondition(
            invitationRequest?.url?.absoluteString
                == "http://127.0.0.1:8787/v1/workspaces/invitations"
        )
        precondition(
            invitationRequest?.value(forHTTPHeaderField: "Authorization")
                == "Bearer test-token"
        )
        precondition(
            String(data: invitationRequest?.httpBody ?? Data(), encoding: .utf8)?
                .contains(#""invitedPrincipalId":"principal-2""#) == true
        )

        let transitionRequest = InvitationRequest(
            workspaceId: "team",
            invitationId: "invite-1",
            invitedPrincipalId: nil,
            role: nil,
            ttlSeconds: nil,
            requestId: "request-2"
        )
        let accepted: InvitationResponse = try await client.acceptWorkspaceInvitation(
            transitionRequest
        )
        precondition(accepted.status == "pending")
        invitationRequest = await transport.request
        precondition(
            invitationRequest?.url?.absoluteString
                == "http://127.0.0.1:8787/v1/workspaces/invitations/accept"
        )

        let revoked: InvitationResponse = try await client.revokeWorkspaceInvitation(
            transitionRequest
        )
        precondition(revoked.status == "pending")
        invitationRequest = await transport.request
        precondition(
            invitationRequest?.url?.absoluteString
                == "http://127.0.0.1:8787/v1/workspaces/invitations/revoke"
        )

        let invitations: InvitationListResponse = try await client.listWorkspaceInvitations(
            workspaceID: "team/name",
            status: "accepted",
            limit: 20
        )
        precondition(invitations.workspaceId == "team/name")
        precondition(invitations.invitations.isEmpty)
        invitationRequest = await transport.request
        precondition(invitationRequest?.httpMethod == "GET")
        precondition(invitationRequest?.httpBody == nil)
        precondition(
            invitationRequest?.url?.absoluteString
                == "http://127.0.0.1:8787/v1/workspaces/invitations?workspaceId=team/name&status=accepted&limit=20"
        )

        do {
            _ = try RembraneClient(
                baseURL: URL(string: "http://memory.example.test/v1")!,
                token: "token",
                transport: transport
            )
            preconditionFailure("unsafe endpoint must be rejected")
        } catch is RembraneAPIError {
            // Expected.
        }

        let shareTransport = MockTransport()
        let shareClient = try RembraneMobileShareClient(
            baseURL: URL(string: "http://127.0.0.1:8791")!,
            transport: shareTransport,
            signer: MockShareSigner()
        )
        try await shareClient.share(
            RembraneMobileShareEnvelope(
                accountID: "account_01",
                deviceID: "device_01",
                eventID: "share_01",
                text: "Continue in another assistant",
                sharedAtEpochSeconds: 1_792_867_200
            )
        )
        let shareRequest = await shareTransport.request
        precondition(shareRequest?.httpMethod == "POST")
        precondition(
            shareRequest?.url?.absoluteString == "http://127.0.0.1:8791/v1/shares"
        )
        precondition(
            shareRequest?.value(forHTTPHeaderField: "X-Rembrane-Signature-256")
                == "sha256=" + String(repeating: "a", count: 64)
        )
        precondition(
            String(data: shareRequest?.httpBody ?? Data(), encoding: .utf8)?
                .contains(#""device_id":"device_01""#) == true
        )

        let coordinatedTransport = MockTransport()
        let coordinatedClient = try RembraneMobileShareClient(
            baseURL: URL(string: "http://127.0.0.1:8791")!,
            transport: coordinatedTransport,
            signer: MockShareSigner()
        )
        let coordinator = try RembraneExplicitShareCoordinator(
            accountID: "account_01",
            deviceID: "device_01",
            submitter: coordinatedClient
        )
        try await coordinator.shareSelectedText(
            "User-selected iMessage text",
            eventID: "share_coordinated_01",
            sharedAtEpochSeconds: 1_792_867_200
        )
        let coordinatedRequest = await coordinatedTransport.request
        precondition(
            String(data: coordinatedRequest?.httpBody ?? Data(), encoding: .utf8)?
                .contains(#""event_id":"share_coordinated_01""#) == true
        )
        do {
            try await coordinator.shareSelectedText(
                " ",
                eventID: "invalid",
                sharedAtEpochSeconds: 1_792_867_200
            )
            preconditionFailure("empty selected text must be rejected")
        } catch let error as RembraneAPIError {
            precondition(error.code == "invalid_share_text")
        }

        #if canImport(CryptoKit)
        let cryptoSigner = try CryptoKitMobileShareSigner(
            secret: Data(repeating: 7, count: 32)
        )
        let signature = try cryptoSigner.signatureHeader(
            for: Data("explicit share".utf8)
        )
        precondition(signature.hasPrefix("sha256="))
        precondition(signature.count == 71)
        #endif

        #if canImport(Security)
        do {
            _ = try KeychainMobileShareEnrollmentStore(service: " invalid ")
            preconditionFailure("unsafe Keychain metadata must be rejected")
        } catch let error as RembraneAPIError {
            precondition(error.code == "invalid_keychain_configuration")
        }
        let generatedSecret = try KeychainMobileShareEnrollmentStore
            .generateSigningSecret()
        precondition(generatedSecret.count == 32)
        do {
            _ = try KeychainMobileShareEnrollmentStore.generateSigningSecret(
                byteCount: 16
            )
            preconditionFailure("short generated signing keys must be rejected")
        } catch let error as RembraneAPIError {
            precondition(error.code == "invalid_signing_key_size")
        }
        #endif
    }
}
