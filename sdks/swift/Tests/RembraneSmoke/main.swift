import Foundation
import Rembrane

private actor MockTransport: RembraneTransport {
    private(set) var request: URLRequest?

    func send(
        _ request: URLRequest,
        maximumResponseBytes: Int
    ) async throws -> RembraneHTTPResponse {
        self.request = request
        return RembraneHTTPResponse(
            status: 200,
            headers: ["content-type": "application/json"],
            body: Data(#"{"events":[]}"#.utf8)
        )
    }
}

private struct AuditResponse: Decodable {
    let events: [String]
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
    }
}
