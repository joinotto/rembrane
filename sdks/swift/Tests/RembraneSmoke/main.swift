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
    }
}
