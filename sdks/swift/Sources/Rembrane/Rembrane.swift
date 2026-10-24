import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
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

    private func execute<Response: Decodable>(
        method: String,
        path: String,
        body: Data?,
        as responseType: Response.Type
    ) async throws -> Response {
        guard let url = URL(string: baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path) else {
            throw RembraneAPIError(status: 0, code: "invalid_endpoint", message: "Invalid request URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
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
        guard response.headers["content-type"]?.lowercased().hasPrefix("application/json") == true else {
            throw RembraneAPIError(
                status: response.status,
                code: "invalid_response",
                message: "Expected JSON response"
            )
        }
        if !(200..<300).contains(response.status) {
            let problem = (try? decoder.decode(Problem.self, from: response.body))
            throw RembraneAPIError(
                status: response.status,
                code: problem?.code ?? "request_failed",
                message: problem?.message ?? "Rembrane request failed"
            )
        }
        return try decoder.decode(responseType, from: response.body)
    }
}

private struct Problem: Decodable {
    let code: String
    let message: String
}
