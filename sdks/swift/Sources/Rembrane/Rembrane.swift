import Foundation
import CoreFoundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

public struct RembraneHTTPResponse: Sendable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data

    public init(status: Int, headers: [String: String], body: Data) {
        self.status = status
        self.headers = headers
        self.body = body
    }
}

public protocol RembraneTransport: Sendable {
    func send(_ request: URLRequest, maximumResponseBytes: Int) async throws
        -> RembraneHTTPResponse
}

public struct RembraneAPIError: Error, Equatable, Sendable {
    public let status: Int
    public let code: String
    public let message: String
}

public enum PortableExportFormat: String, Sendable {
    case jsonl
    case markdown
    case graphJSON = "graph-json"

    fileprivate var contentType: String {
        switch self {
        case .jsonl:
            "application/x-ndjson"
        case .markdown:
            "text/markdown; charset=utf-8"
        case .graphJSON:
            "application/vnd.rembrane.knowledge-graph+json"
        }
    }

    fileprivate var filename: String {
        switch self {
        case .jsonl:
            "rembrane-memories.jsonl"
        case .markdown:
            "rembrane-memories.md"
        case .graphJSON:
            "rembrane-knowledge-graph.json"
        }
    }
}

public struct PortableExport: Sendable {
    public let format: PortableExportFormat
    public let contentType: String
    public let filename: String
    public let body: Data
}

public struct PortableImportResult: Decodable, Equatable, Sendable {
    public let imported: Int
    public let status: String

    public init(imported: Int, status: String) {
        self.imported = imported
        self.status = status
    }
}

public struct MemoryDiscovery: Sendable {
    public let providerID: String
    public let providerName: String
    public let protocolVersions: [String]
    public let apiEndpoint: URL
    public let processingModes: [String]
    public let importFormats: [String]
    public let exportFormats: [String]
    public let rawDocument: Data
}

public enum ChannelProcessorChannel: String, Codable, Sendable {
    case whatsAppBusiness = "whatsapp-business"
    case iMessageExtension = "imessage-extension"
    case mobileShare = "mobile-share"
}

public struct ChannelProcessorMessage: Codable, Equatable, Sendable {
    public let protocolVersion: String
    public let channel: ChannelProcessorChannel
    public let eventId: String
    public let workspaceId: String
    public let principalId: String
    public let clientId: String
    public let text: String
    public let receivedAtEpochSeconds: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case protocolVersion
        case channel
        case eventId
        case workspaceId
        case principalId
        case clientId
        case text
        case receivedAtEpochSeconds
    }

    public init(
        protocolVersion: String = "0.1",
        channel: ChannelProcessorChannel,
        eventId: String,
        workspaceId: String,
        principalId: String,
        clientId: String,
        text: String,
        receivedAtEpochSeconds: UInt64
    ) throws {
        guard protocolVersion == "0.1",
              Self.validToken(eventId, maximumBytes: 256),
              Self.validToken(workspaceId, maximumBytes: 255),
              Self.validToken(principalId, maximumBytes: 255),
              Self.validToken(clientId, maximumBytes: 255),
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              text.utf8.count <= 16_384,
              receivedAtEpochSeconds > 0 else {
            throw Self.invalid()
        }
        self.protocolVersion = protocolVersion
        self.channel = channel
        self.eventId = eventId
        self.workspaceId = workspaceId
        self.principalId = principalId
        self.clientId = clientId
        self.text = text
        self.receivedAtEpochSeconds = receivedAtEpochSeconds
    }

    public init(from decoder: Decoder) throws {
        let dynamic = try decoder.container(keyedBy: DynamicCodingKey.self)
        let expected = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(dynamic.allKeys.map(\.stringValue)) == expected else {
            throw Self.invalid()
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            protocolVersion: values.decode(String.self, forKey: .protocolVersion),
            channel: values.decode(ChannelProcessorChannel.self, forKey: .channel),
            eventId: values.decode(String.self, forKey: .eventId),
            workspaceId: values.decode(String.self, forKey: .workspaceId),
            principalId: values.decode(String.self, forKey: .principalId),
            clientId: values.decode(String.self, forKey: .clientId),
            text: values.decode(String.self, forKey: .text),
            receivedAtEpochSeconds: values.decode(
                UInt64.self,
                forKey: .receivedAtEpochSeconds
            )
        )
    }

    private static func validToken(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes
            && value.unicodeScalars.allSatisfy {
                !CharacterSet.whitespacesAndNewlines.contains($0)
                    && !CharacterSet.controlCharacters.contains($0)
            }
    }

    private static func invalid() -> RembraneAPIError {
        RembraneAPIError(
            status: 0,
            code: "invalid_channel_processor_message",
            message: "Invalid Rembrane channel processor message"
        )
    }
}

public enum ChannelProcessorStatus: String, Codable, Sendable {
    case processed
    case duplicate
}

public struct ChannelProcessorAcknowledgement: Codable, Equatable, Sendable {
    public let protocolVersion: String
    public let eventId: String
    public let status: ChannelProcessorStatus

    public init(eventId: String, status: ChannelProcessorStatus) throws {
        guard !eventId.isEmpty, eventId.utf8.count <= 256,
              eventId.unicodeScalars.allSatisfy({
                  !CharacterSet.whitespacesAndNewlines.contains($0)
                      && !CharacterSet.controlCharacters.contains($0)
              }) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_channel_processor_acknowledgement",
                message: "Invalid Rembrane channel processor acknowledgement"
            )
        }
        self.protocolVersion = "0.1"
        self.eventId = eventId
        self.status = status
    }
}

private struct DynamicCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}

private final class RedirectRejectingDelegate: NSObject, URLSessionTaskDelegate,
    @unchecked Sendable
{
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public struct URLSessionRembraneTransport: RembraneTransport {
    public init() {}

    public func send(
        _ request: URLRequest,
        maximumResponseBytes: Int
    ) async throws -> RembraneHTTPResponse {
        let delegate = RedirectRejectingDelegate()
        let session = URLSession(
            configuration: .ephemeral,
            delegate: delegate,
            delegateQueue: nil
        )
        defer { session.invalidateAndCancel() }
        let (body, response) = try await session.data(for: request)
        guard body.count <= maximumResponseBytes else {
            throw RembraneAPIError(
                status: 0,
                code: "response_too_large",
                message: "Response exceeded limit"
            )
        }
        guard let http = response as? HTTPURLResponse else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_response",
                message: "Expected an HTTP response"
            )
        }
        let headers = http.allHeaderFields.reduce(into: [String: String]()) { result, item in
            result[String(describing: item.key).lowercased()] = String(describing: item.value)
        }
        return RembraneHTTPResponse(status: http.statusCode, headers: headers, body: body)
    }
}

public struct RembraneClient<Transport: RembraneTransport>: Sendable {
    private let baseURL: URL
    private let token: String
    private let transport: Transport
    private let maximumResponseBytes: Int
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(
        baseURL: URL,
        token: String,
        transport: Transport,
        maximumResponseBytes: Int = 1_048_576
    ) throws {
        let loopback = ["localhost", "127.0.0.1", "::1"].contains(baseURL.host ?? "")
        guard baseURL.scheme == "https" || (baseURL.scheme == "http" && loopback) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_endpoint",
                message: "Rembrane requires HTTPS or an explicit loopback URL"
            )
        }
        guard baseURL.user == nil, baseURL.password == nil,
              baseURL.query == nil, baseURL.fragment == nil else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_endpoint",
                message: "Base URL must not contain credentials, query, or fragment"
            )
        }
        guard !token.isEmpty, maximumResponseBytes > 0 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_configuration",
                message: "Token and positive response limit are required"
            )
        }
        self.baseURL = baseURL
        self.token = token
        self.transport = transport
        self.maximumResponseBytes = maximumResponseBytes
    }

    public func post<Request: Encodable, Response: Decodable>(
        _ path: String,
        request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await execute(method: "POST", path: path, body: encoder.encode(request), as: responseType)
    }

    public func discover() async throws -> MemoryDiscovery {
        guard var components = URLComponents(
            url: baseURL,
            resolvingAgainstBaseURL: false
        ) else {
            throw Self.invalidDiscovery()
        }
        components.path = "/.well-known/ai-memory"
        components.query = nil
        components.fragment = nil
        guard let url = components.url else {
            throw Self.invalidDiscovery()
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let response = try await transport.send(
            request,
            maximumResponseBytes: maximumResponseBytes
        )
        try enforceResponseLimit(response)
        guard (200..<300).contains(response.status),
              response.header("content-type").lowercased()
                .hasPrefix("application/json") else {
            if !(200..<300).contains(response.status) {
                throw problem(from: response)
            }
            throw Self.invalidDiscovery()
        }
        return try Self.validateDiscovery(response.body, expectedAPI: baseURL)
    }

    public func createWorkspaceInvitation<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/workspaces/invitations", request: request, as: responseType)
    }

    public func resolveContext<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/context/resolve", request: request, as: responseType)
    }

    public func resolveGraphContext<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/graph/context/resolve", request: request, as: responseType)
    }

    public func rememberPreference<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/memories/preferences", request: request, as: responseType)
    }

    public func recordWorkTrace<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/memories/work-traces", request: request, as: responseType)
    }

    public func correctMemory<Request: Encodable, Response: Decodable>(
        memoryID: String,
        request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try Self.requireOpaqueID(memoryID, field: "memoryID")
        return try await post(
            "/memories/\(memoryID)/correction",
            request: request,
            as: responseType
        )
    }

    public func deleteMemory<Request: Encodable, Response: Decodable>(
        memoryID: String,
        request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try Self.requireOpaqueID(memoryID, field: "memoryID")
        return try await post(
            "/memories/\(memoryID)/deletion",
            request: request,
            as: responseType
        )
    }

    public func checkpointActivity<Request: Encodable, Response: Decodable>(
        activityID: String,
        request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try Self.requireOpaqueID(activityID, field: "activityID")
        return try await post(
            "/activities/\(activityID)/checkpoint",
            request: request,
            as: responseType
        )
    }

    public func resumeActivity<Response: Decodable>(
        activityID: String,
        workspaceID: String,
        subjectID: String,
        purpose: String? = nil,
        stateFingerprint: String? = nil,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try Self.requireOpaqueID(activityID, field: "activityID")
        try Self.requireOpaqueID(workspaceID, field: "workspaceID")
        try Self.requireOpaqueID(subjectID, field: "subjectID")
        var items = [
            URLQueryItem(name: "workspaceId", value: workspaceID),
            URLQueryItem(name: "subjectId", value: subjectID),
        ]
        if let purpose {
            items.append(URLQueryItem(name: "purpose", value: purpose))
        }
        if let stateFingerprint {
            items.append(
                URLQueryItem(name: "stateFingerprint", value: stateFingerprint)
            )
        }
        let query = try Self.portabilityQuery(items)
        return try await execute(
            method: "GET",
            path: "/activities/\(activityID)/resume?\(query)",
            body: nil,
            as: responseType
        )
    }

    public func createTrip<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/travel/trips", request: request, as: responseType)
    }

    public func addTripParticipant<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/travel/trip-participants",
            request: request,
            as: responseType
        )
    }

    public func addTripConstraint<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/travel/trip-constraints",
            request: request,
            as: responseType
        )
    }

    public func recordTripDecision<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/travel/trip-decisions",
            request: request,
            as: responseType
        )
    }

    public func captureBookingResearch<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/travel/booking-research",
            request: request,
            as: responseType
        )
    }

    public func resolveTravelContext<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/travel/context/resolve",
            request: request,
            as: responseType
        )
    }

    public func acceptWorkspaceInvitation<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/workspaces/invitations/accept", request: request, as: responseType)
    }

    public func revokeWorkspaceInvitation<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/workspaces/invitations/revoke", request: request, as: responseType)
    }

    public func rotateWorkspaceKey<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/workspaces/key-rotation",
            request: request,
            as: responseType
        )
    }

    public func setRetentionPolicy<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/retention/policy", request: request, as: responseType)
    }

    public func placeLegalHold<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/retention/legal-holds",
            request: request,
            as: responseType
        )
    }

    public func releaseLegalHold<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post(
            "/retention/legal-holds/release",
            request: request,
            as: responseType
        )
    }

    public func executeRetentionPurge<Request: Encodable, Response: Decodable>(
        _ request: Request,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        try await post("/retention/purge", request: request, as: responseType)
    }

    public func listWorkspaceInvitations<Response: Decodable>(
        workspaceID: String,
        status: String? = nil,
        limit: Int? = nil,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "workspaceId", value: workspaceID),
            status.map { URLQueryItem(name: "status", value: $0) },
            limit.map { URLQueryItem(name: "limit", value: String($0)) },
        ].compactMap { $0 }
        return try await execute(
            method: "GET",
            path: "/workspaces/invitations?\(components.percentEncodedQuery ?? "")",
            body: nil,
            as: responseType
        )
    }

    public func listAdministrativeAudit<Response: Decodable>(
        workspaceID: String,
        afterEpochSeconds: UInt64? = nil,
        limit: Int? = nil,
        as responseType: Response.Type = Response.self
    ) async throws -> Response {
        var components = URLComponents()
        components.queryItems = [
            URLQueryItem(name: "workspaceId", value: workspaceID),
            afterEpochSeconds.map {
                URLQueryItem(name: "afterEpochSeconds", value: String($0))
            },
            limit.map { URLQueryItem(name: "limit", value: String($0)) },
        ].compactMap { $0 }
        return try await execute(
            method: "GET",
            path: "/administrative-audit?\(components.percentEncodedQuery ?? "")",
            body: nil,
            as: responseType
        )
    }

    public func exportPortableData(
        workspaceID: String,
        subjectID: String,
        format: PortableExportFormat
    ) async throws -> PortableExport {
        try Self.requireOpaqueID(workspaceID, field: "workspaceID")
        try Self.requireOpaqueID(subjectID, field: "subjectID")
        let query = try Self.portabilityQuery([
            URLQueryItem(name: "workspaceId", value: workspaceID),
            URLQueryItem(name: "subjectId", value: subjectID),
            URLQueryItem(name: "format", value: format.rawValue),
        ])
        var request = try authenticatedRequest(
            path: "/exports?\(query)",
            method: "POST"
        )
        request.setValue(format.contentType, forHTTPHeaderField: "Accept")
        let response = try await transport.send(
            request,
            maximumResponseBytes: maximumResponseBytes
        )
        try enforceResponseLimit(response)
        if !(200..<300).contains(response.status) {
            throw problem(from: response)
        }
        guard response.header("content-type").lowercased()
                == format.contentType.lowercased(),
              response.header("content-disposition")
                == "attachment; filename=\"\(format.filename)\"",
              response.header("cache-control").lowercased() == "no-store",
              response.header("x-content-type-options").lowercased() == "nosniff"
        else {
            throw RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Portable export metadata was invalid"
            )
        }
        return PortableExport(
            format: format,
            contentType: response.header("content-type"),
            filename: format.filename,
            body: response.body
        )
    }

    public func importPortableMemories(
        workspaceID: String,
        subjectID: String,
        expectedPreviousSequence: UInt64,
        jsonl: Data
    ) async throws -> PortableImportResult {
        try Self.requireOpaqueID(workspaceID, field: "workspaceID")
        try Self.requireOpaqueID(subjectID, field: "subjectID")
        guard !jsonl.isEmpty, jsonl.count <= 67_108_864 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_import",
                message: "Portable import archive size is invalid"
            )
        }
        let query = try Self.portabilityQuery([
            URLQueryItem(name: "workspaceId", value: workspaceID),
            URLQueryItem(name: "subjectId", value: subjectID),
            URLQueryItem(
                name: "expectedPreviousSequence",
                value: String(expectedPreviousSequence)
            ),
        ])
        var request = try authenticatedRequest(
            path: "/imports?\(query)",
            method: "POST"
        )
        request.httpBody = jsonl
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(
            "application/x-ndjson",
            forHTTPHeaderField: "Content-Type"
        )
        let response = try await transport.send(
            request,
            maximumResponseBytes: maximumResponseBytes
        )
        try enforceResponseLimit(response)
        if !(200..<300).contains(response.status) {
            throw problem(from: response)
        }
        guard response.header("content-type").lowercased()
                .hasPrefix("application/json") else {
            throw RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Expected JSON response"
            )
        }
        guard let object = try? JSONSerialization.jsonObject(with: response.body),
              let fields = object as? [String: Any],
              Set(fields.keys) == ["imported", "status"],
              let imported = fields["imported"] as? Int,
              (1...10_000).contains(imported),
              fields["status"] as? String == "proposed" else {
            throw RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Portable import response was invalid"
            )
        }
        return PortableImportResult(imported: imported, status: "proposed")
    }

    private func execute<Response: Decodable>(
        method: String,
        path: String,
        body: Data?,
        as responseType: Response.Type
    ) async throws -> Response {
        var request = try authenticatedRequest(path: path, method: method)
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let response = try await transport.send(
            request,
            maximumResponseBytes: maximumResponseBytes
        )
        try enforceResponseLimit(response)
        guard response.header("content-type").lowercased()
                .hasPrefix("application/json") else {
            throw RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Expected JSON response"
            )
        }
        if !(200..<300).contains(response.status) {
            throw problem(from: response)
        }
        return try decoder.decode(responseType, from: response.body)
    }

    private func authenticatedRequest(
        path: String,
        method: String
    ) throws -> URLRequest {
        let root = baseURL.absoluteString.trimmingCharacters(
            in: CharacterSet(charactersIn: "/")
        )
        guard let url = URL(string: root + path) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_endpoint",
                message: "Invalid request URL"
            )
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return request
    }

    private func enforceResponseLimit(_ response: RembraneHTTPResponse) throws {
        guard response.body.count <= maximumResponseBytes else {
            throw RembraneAPIError(
                status: response.status,
                code: "response_too_large",
                message: "Response exceeded limit"
            )
        }
    }

    private func problem(from response: RembraneHTTPResponse) -> RembraneAPIError {
        guard response.header("content-type").lowercased()
                .hasPrefix("application/json") else {
            return RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Expected JSON problem response"
            )
        }
        let decoded = try? decoder.decode(Problem.self, from: response.body)
        return RembraneAPIError(
            status: response.status,
            code: decoded?.code ?? "request_failed",
            message: decoded?.message ?? "Rembrane request failed"
        )
    }

    private static func portabilityQuery(
        _ items: [URLQueryItem]
    ) throws -> String {
        var components = URLComponents()
        components.queryItems = items
        guard let query = components.percentEncodedQuery, !query.isEmpty else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_request",
                message: "Portable request query was invalid"
            )
        }
        return query
    }

    private static func requireOpaqueID(
        _ value: String,
        field: String
    ) throws {
        let allowed = CharacterSet(
            charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
        )
        guard !value.isEmpty, value.utf8.count <= 255,
              value.unicodeScalars.first.map(CharacterSet.alphanumerics.contains)
                == true,
              value.unicodeScalars.allSatisfy(allowed.contains) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_identifier",
                message: "\(field) must be a bounded opaque identifier"
            )
        }
    }

    private static func validateDiscovery(
        _ data: Data,
        expectedAPI: URL
    ) throws -> MemoryDiscovery {
        guard let root = try? JSONSerialization.jsonObject(with: data),
              let document = root as? [String: Any],
              hasOnlyKeys(
                document,
                allowed: [
                    "provider", "protocolVersions", "endpoints", "capabilities",
                    "limits", "privacy", "extensions",
                ]
              ),
              let provider = document["provider"] as? [String: Any],
              hasOnlyKeys(
                provider,
                allowed: ["id", "name", "implementation"]
              ),
              let providerID = provider["id"] as? String,
              boundedText(providerID),
              let providerName = provider["name"] as? String,
              boundedText(providerName),
              optionalBoundedText(provider, key: "implementation"),
              let versions = uniqueStrings(document["protocolVersions"]),
              !versions.isEmpty,
              versions.allSatisfy(validProtocolVersion),
              let endpoints = document["endpoints"] as? [String: Any],
              hasOnlyKeys(
                endpoints,
                allowed: ["api", "oauthAuthorization", "oauthToken", "mcp"]
              ),
              let apiText = endpoints["api"] as? String,
              normalizedAPIRoot(apiText) == normalizedAPIRoot(expectedAPI.absoluteString),
              optionalAbsoluteURL(
                endpoints,
                key: "oauthAuthorization",
                requireHTTPS: true
              ),
              optionalAbsoluteURL(
                endpoints,
                key: "oauthToken",
                requireHTTPS: true
              ),
              optionalAbsoluteURL(endpoints, key: "mcp", requireHTTPS: false),
              let apiEndpoint = URL(string: apiText),
              let capabilities = document["capabilities"] as? [String: Any],
              hasOnlyKeys(
                capabilities,
                allowed: [
                    "contextResolution", "questionResolution", "memoryProposal",
                    "activityCheckpoint", "disclosureReceipt",
                    "deletionPropagation", "sync", "imports", "exports",
                ]
              ),
              requiredBooleans(
                capabilities,
                keys: [
                    "contextResolution", "memoryProposal", "activityCheckpoint",
                    "disclosureReceipt", "deletionPropagation",
                ]
              ),
              optionalBooleans(
                capabilities,
                keys: ["questionResolution", "sync"]
              ),
              optionalUniqueStrings(capabilities, key: "imports"),
              optionalUniqueStrings(capabilities, key: "exports"),
              validLimits(document["limits"]),
              let privacy = document["privacy"] as? [String: Any],
              hasOnlyKeys(
                privacy,
                allowed: [
                    "processingModes", "disclosureReceipts",
                    "plaintextProcessingLocation",
                ]
              ),
              privacy["disclosureReceipts"] as? Bool == true,
              let modes = uniqueStrings(privacy["processingModes"]),
              !modes.isEmpty,
              modes.allSatisfy(
                Set(["hosted", "customer-gateway", "local-only"]).contains
              ),
              validPlaintextLocation(privacy),
              validExtensions(document["extensions"])
        else {
            throw invalidDiscovery()
        }
        return MemoryDiscovery(
            providerID: providerID,
            providerName: providerName,
            protocolVersions: versions,
            apiEndpoint: apiEndpoint,
            processingModes: modes,
            importFormats: uniqueStrings(capabilities["imports"]) ?? [],
            exportFormats: uniqueStrings(capabilities["exports"]) ?? [],
            rawDocument: data
        )
    }

    private static func hasOnlyKeys(
        _ object: [String: Any],
        allowed: Set<String>
    ) -> Bool {
        Set(object.keys).isSubset(of: allowed)
    }

    private static func boundedText(_ value: String) -> Bool {
        !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && value.utf8.count <= 255
    }

    private static func optionalBoundedText(
        _ object: [String: Any],
        key: String
    ) -> Bool {
        guard let value = object[key] else { return true }
        guard let text = value as? String else { return false }
        return text.utf8.count <= 255
    }

    private static func uniqueStrings(_ value: Any?) -> [String]? {
        guard let values = value as? [Any],
              values.allSatisfy({ $0 is String }) else {
            return nil
        }
        let strings = values.compactMap { $0 as? String }
        return Set(strings).count == strings.count ? strings : nil
    }

    private static func validProtocolVersion(_ value: String) -> Bool {
        value.range(
            of: #"^[0-9]+\.[0-9]+$"#,
            options: .regularExpression
        ) != nil
    }

    private static func normalizedAPIRoot(_ value: String) -> String? {
        guard let url = URL(string: value),
              let scheme = url.scheme,
              let host = url.host,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil,
              url.path.hasSuffix("/v1") else {
            return nil
        }
        let loopback = ["localhost", "127.0.0.1", "::1"].contains(host)
        guard scheme == "https" || (scheme == "http" && loopback) else {
            return nil
        }
        return url.absoluteString.trimmingCharacters(
            in: CharacterSet(charactersIn: "/")
        )
    }

    private static func optionalAbsoluteURL(
        _ object: [String: Any],
        key: String,
        requireHTTPS: Bool
    ) -> Bool {
        guard let value = object[key] else { return true }
        guard let text = value as? String,
              let url = URL(string: text),
              url.host != nil,
              !requireHTTPS || url.scheme == "https" else {
            return false
        }
        return true
    }

    private static func requiredBooleans(
        _ object: [String: Any],
        keys: Set<String>
    ) -> Bool {
        keys.allSatisfy { object[$0] is Bool }
    }

    private static func optionalBooleans(
        _ object: [String: Any],
        keys: Set<String>
    ) -> Bool {
        keys.allSatisfy { object[$0] == nil || object[$0] is Bool }
    }

    private static func optionalUniqueStrings(
        _ object: [String: Any],
        key: String
    ) -> Bool {
        object[key] == nil || uniqueStrings(object[key]) != nil
    }

    private static func validLimits(_ value: Any?) -> Bool {
        guard let value else { return true }
        guard let limits = value as? [String: Any],
              hasOnlyKeys(
                limits,
                allowed: [
                    "maximumContextItems", "maximumContextBytes",
                    "maximumEventBytes",
                ]
              ) else {
            return false
        }
        return limits.values.allSatisfy {
            guard let number = $0 as? NSNumber,
                  CFGetTypeID(number) != CFBooleanGetTypeID() else {
                return false
            }
            return number.int64Value > 0
                && NSNumber(value: number.int64Value) == number
        }
    }

    private static func validPlaintextLocation(
        _ privacy: [String: Any]
    ) -> Bool {
        guard let value = privacy["plaintextProcessingLocation"] else {
            return true
        }
        guard let location = value as? String else { return false }
        return Set([
            "provider", "customer-gateway", "user-device", "mode-dependent",
        ]).contains(location)
    }

    private static func validExtensions(_ value: Any?) -> Bool {
        guard let value else { return true }
        guard let extensions = value as? [String: Any] else { return false }
        return extensions.keys.allSatisfy {
            $0.range(
                of: #"^[a-z0-9][a-z0-9.-]+/[A-Za-z0-9._-]+$"#,
                options: .regularExpression
            ) != nil
        }
    }

    private static func invalidDiscovery() -> RembraneAPIError {
        RembraneAPIError(
            status: 200,
            code: "invalid_discovery",
            message:
                "Provider discovery was invalid or did not match the configured API"
        )
    }
}

private extension RembraneHTTPResponse {
    func header(_ name: String) -> String {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?
            .value ?? ""
    }
}

private struct Problem: Decodable {
    let code: String
    let message: String
}

public protocol RembraneMobileShareSigner: Sendable {
    func signatureHeader(for body: Data) throws -> String
}

#if canImport(Security)
public struct RembraneMobileShareEnrollment: Sendable {
    public let accountID: String
    public let deviceID: String
    public let signingSecret: Data

    public init(accountID: String, deviceID: String, signingSecret: Data) {
        self.accountID = accountID
        self.deviceID = deviceID
        self.signingSecret = signingSecret
    }
}

private struct StoredMobileShareEnrollment: Codable {
    let version: Int
    let accountID: String
    let deviceID: String
    let signingSecret: Data
}

/// Reads mobile-share enrollment material from generic-password Keychain
/// storage shared by a companion app and its explicitly entitled extensions.
public struct KeychainMobileShareEnrollmentStore: Sendable {
    private static let bundleAccount = "rembrane.enrollment-v1"
    private static let maximumBundleBytes = 4_096
    private static let legacyAccounts = [
        "rembrane.account-id",
        "rembrane.device-id",
        "rembrane.signing-secret",
    ]
    private let service: String
    private let accessGroup: String?

    public init(
        service: String = "org.rembrane.mobile-share",
        accessGroup: String? = nil
    ) throws {
        guard Self.validMetadata(service),
              accessGroup.map(Self.validMetadata) ?? true else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_keychain_configuration",
                message: "Keychain service and access group must be bounded metadata"
            )
        }
        self.service = service
        self.accessGroup = accessGroup
    }

    /// Generates a new device-local signing secret with the operating
    /// system's cryptographically secure random source.
    public static func generateSigningSecret(byteCount: Int = 32) throws -> Data {
        guard (32...64).contains(byteCount) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_signing_key_size",
                message: "Mobile-share signing keys must contain 32 to 64 bytes"
            )
        }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw RembraneAPIError(
                status: 0,
                code: "secure_random_unavailable",
                message: "A device signing key could not be generated"
            )
        }
        return Data(bytes)
    }

    public func load() throws -> RembraneMobileShareEnrollment {
        if let bundle = try readDataIfPresent(account: Self.bundleAccount) {
            guard bundle.count <= Self.maximumBundleBytes,
                  let stored = try? PropertyListDecoder().decode(
                    StoredMobileShareEnrollment.self,
                    from: bundle
                  ),
                  stored.version == 1 else {
                throw unavailable()
            }
            return try validatedEnrollment(
                accountID: stored.accountID,
                deviceID: stored.deviceID,
                signingSecret: stored.signingSecret
            )
        }

        // Read compatibility for pre-alpha installations that provisioned
        // three independent items. The next successful save migrates them to
        // the atomic bundle.
        let accountID = try readUTF8(account: "rembrane.account-id")
        let deviceID = try readUTF8(account: "rembrane.device-id")
        let signingSecret = try readData(account: "rembrane.signing-secret")
        return try validatedEnrollment(
            accountID: accountID,
            deviceID: deviceID,
            signingSecret: signingSecret
        )
    }

    /// Atomically stores or replaces one versioned enrollment bundle under
    /// this service and optional access group. It is available only while the
    /// device is unlocked and does not migrate to another device backup.
    public func save(_ enrollment: RembraneMobileShareEnrollment) throws {
        let validated = try validatedEnrollment(
            accountID: enrollment.accountID,
            deviceID: enrollment.deviceID,
            signingSecret: enrollment.signingSecret
        )
        let stored = StoredMobileShareEnrollment(
            version: 1,
            accountID: validated.accountID,
            deviceID: validated.deviceID,
            signingSecret: validated.signingSecret
        )
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let bundle = try encoder.encode(stored)
        guard bundle.count <= Self.maximumBundleBytes else {
            throw keychainFailure()
        }
        try upsert(account: Self.bundleAccount, data: bundle)
        try removeAccounts(Self.legacyAccounts)
    }

    /// Removes the atomic bundle and any pre-alpha legacy items. Missing items
    /// are treated as already revoked.
    public func remove() throws {
        try removeAccounts([Self.bundleAccount] + Self.legacyAccounts)
    }

    private func removeAccounts(_ accounts: [String]) throws {
        for account in accounts {
            let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw keychainFailure()
            }
        }
    }

    private func readUTF8(account: String) throws -> String {
        let data = try readData(account: account)
        guard let value = String(data: data, encoding: .utf8),
              Self.validMetadata(value) else {
            throw unavailable()
        }
        return value
    }

    private func readData(account: String) throws -> Data {
        guard let data = try readDataIfPresent(account: account) else {
            throw unavailable()
        }
        return data
    }

    private func readDataIfPresent(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess,
              let data = result as? Data, !data.isEmpty else {
            throw unavailable()
        }
        return data
    }

    private func upsert(account: String, data: Data) throws {
        let query = baseQuery(account: account)
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            attributes as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw keychainFailure()
        }
        var item = query
        for (key, value) in attributes {
            item[key] = value
        }
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw keychainFailure()
        }
    }

    private func baseQuery(account: String) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup] = accessGroup
        }
        return query
    }

    private static func validMetadata(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 256
            && value == value.trimmingCharacters(in: .whitespacesAndNewlines)
            && value.unicodeScalars.allSatisfy {
                $0.properties.generalCategory != .control
            }
    }

    private func validatedEnrollment(
        accountID: String,
        deviceID: String,
        signingSecret: Data
    ) throws -> RembraneMobileShareEnrollment {
        guard Self.validMetadata(accountID),
              Self.validMetadata(deviceID),
              (32...64).contains(signingSecret.count) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_enrollment",
                message: "Enrollment identifiers and signing key are invalid"
            )
        }
        return RembraneMobileShareEnrollment(
            accountID: accountID,
            deviceID: deviceID,
            signingSecret: signingSecret
        )
    }

    private func unavailable() -> RembraneAPIError {
        RembraneAPIError(
            status: 0,
            code: "keychain_item_unavailable",
            message: "Required mobile-share enrollment is unavailable"
        )
    }

    private func keychainFailure() -> RembraneAPIError {
        RembraneAPIError(
            status: 0,
            code: "keychain_operation_failed",
            message: "Mobile-share enrollment could not be updated"
        )
    }
}
#endif

#if canImport(CryptoKit)
public struct CryptoKitMobileShareSigner: RembraneMobileShareSigner {
    private let key: SymmetricKey

    public init(secret: Data) throws {
        guard secret.count >= 32 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_signing_key",
                message: "Mobile-share signing keys require at least 32 bytes"
            )
        }
        self.key = SymmetricKey(data: secret)
    }

    public func signatureHeader(for body: Data) throws -> String {
        let authenticationCode = HMAC<SHA256>.authenticationCode(
            for: body,
            using: key
        )
        let encoded = authenticationCode.map {
            String(format: "%02x", $0)
        }.joined()
        return "sha256=\(encoded)"
    }
}
#endif

public struct RembraneMobileShareEnvelope: Encodable, Sendable {
    public let accountID: String
    public let deviceID: String
    public let eventID: String
    public let text: String
    public let sharedAtEpochSeconds: UInt64

    enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
        case eventID = "event_id"
        case text
        case sharedAtEpochSeconds = "shared_at_epoch_seconds"
    }

    public init(
        accountID: String,
        deviceID: String,
        eventID: String,
        text: String,
        sharedAtEpochSeconds: UInt64
    ) {
        self.accountID = accountID
        self.deviceID = deviceID
        self.eventID = eventID
        self.text = text
        self.sharedAtEpochSeconds = sharedAtEpochSeconds
    }
}

public struct RembraneMobileShareClient<
    Transport: RembraneTransport,
    Signer: RembraneMobileShareSigner
>: Sendable {
    private let baseURL: URL
    private let transport: Transport
    private let signer: Signer
    private let maximumResponseBytes: Int

    public init(
        baseURL: URL,
        transport: Transport,
        signer: Signer,
        maximumResponseBytes: Int = 4_096
    ) throws {
        let loopback = ["localhost", "127.0.0.1", "::1"].contains(baseURL.host ?? "")
        guard baseURL.scheme == "https" || (baseURL.scheme == "http" && loopback) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_endpoint",
                message: "Mobile share requires HTTPS or an explicit loopback URL"
            )
        }
        guard baseURL.user == nil, baseURL.password == nil,
              baseURL.query == nil, baseURL.fragment == nil,
              maximumResponseBytes > 0 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_configuration",
                message: "Safe endpoint and positive response limit are required"
            )
        }
        self.baseURL = baseURL
        self.transport = transport
        self.signer = signer
        self.maximumResponseBytes = maximumResponseBytes
    }

    public func share(_ envelope: RembraneMobileShareEnvelope) async throws {
        let body = try JSONEncoder().encode(envelope)
        let signature = try signer.signatureHeader(for: body)
        let encodedSignature = signature.dropFirst("sha256=".count)
        let lowercaseHex = encodedSignature.allSatisfy {
            ("0"..."9").contains($0) || ("a"..."f").contains($0)
        }
        guard signature.hasPrefix("sha256="), signature.count == 71, lowercaseHex else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_signature",
                message: "Signer must return a sha256 lowercase-hex header"
            )
        }
        let root = baseURL.absoluteString.trimmingCharacters(
            in: CharacterSet(charactersIn: "/")
        )
        guard let url = URL(string: root + "/v1/shares") else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_endpoint",
                message: "Invalid mobile-share URL"
            )
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(signature, forHTTPHeaderField: "X-Rembrane-Signature-256")
        let response = try await transport.send(
            request,
            maximumResponseBytes: maximumResponseBytes
        )
        guard response.body.count <= maximumResponseBytes else {
            throw RembraneAPIError(
                status: response.status,
                code: "response_too_large",
                message: "Response exceeded limit"
            )
        }
        guard (200..<300).contains(response.status) else {
            throw RembraneAPIError(
                status: response.status,
                code: "share_rejected",
                message: "Rembrane rejected the explicit share"
            )
        }
    }
}

public protocol RembraneMobileShareSubmitting: Sendable {
    func share(_ envelope: RembraneMobileShareEnvelope) async throws
}

extension RembraneMobileShareClient: RembraneMobileShareSubmitting {}

public struct RembraneExplicitShareCoordinator<
    Submitter: RembraneMobileShareSubmitting
>: Sendable {
    private let accountID: String
    private let deviceID: String
    private let submitter: Submitter

    public init(
        accountID: String,
        deviceID: String,
        submitter: Submitter
    ) throws {
        guard Self.validIdentifier(accountID),
              Self.validIdentifier(deviceID) else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_share_identity",
                message: "Account and device identifiers must be safe and bounded"
            )
        }
        self.accountID = accountID
        self.deviceID = deviceID
        self.submitter = submitter
    }

    @discardableResult
    public func shareSelectedText(_ text: String) async throws -> String {
        let eventID = UUID().uuidString.lowercased()
        let timestamp = UInt64(Date().timeIntervalSince1970)
        try await shareSelectedText(
            text,
            eventID: eventID,
            sharedAtEpochSeconds: timestamp
        )
        return eventID
    }

    public func shareSelectedText(
        _ text: String,
        eventID: String,
        sharedAtEpochSeconds: UInt64
    ) async throws {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              text.utf8.count <= 16_384 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_share_text",
                message: "Selected text must be non-empty and at most 16384 UTF-8 bytes"
            )
        }
        guard Self.validIdentifier(eventID), sharedAtEpochSeconds > 0 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_share_event",
                message: "Share event identity and timestamp must be valid"
            )
        }
        try await submitter.share(
            RembraneMobileShareEnvelope(
                accountID: accountID,
                deviceID: deviceID,
                eventID: eventID,
                text: text,
                sharedAtEpochSeconds: sharedAtEpochSeconds
            )
        )
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 256
            && !value.utf8.contains {
                $0 <= 0x20 || $0 == 0x7f
            }
    }
}
