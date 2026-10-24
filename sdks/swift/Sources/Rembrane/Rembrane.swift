import Foundation
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

/// Reads mobile-share enrollment material from generic-password Keychain
/// items shared by a companion app and its explicitly entitled extensions.
public struct KeychainMobileShareEnrollmentStore: Sendable {
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
        let accountID = try readUTF8(account: "rembrane.account-id")
        let deviceID = try readUTF8(account: "rembrane.device-id")
        let signingSecret = try readData(account: "rembrane.signing-secret")
        guard signingSecret.count >= 32 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_signing_key",
                message: "Mobile-share signing keys require at least 32 bytes"
            )
        }
        return RembraneMobileShareEnrollment(
            accountID: accountID,
            deviceID: deviceID,
            signingSecret: signingSecret
        )
    }

    /// Stores or replaces enrollment items under this service and optional
    /// access group. Items are available only while the device is unlocked
    /// and do not migrate to another device backup.
    public func save(_ enrollment: RembraneMobileShareEnrollment) throws {
        guard Self.validMetadata(enrollment.accountID),
              Self.validMetadata(enrollment.deviceID),
              enrollment.signingSecret.count >= 32 else {
            throw RembraneAPIError(
                status: 0,
                code: "invalid_enrollment",
                message: "Enrollment identifiers and signing key are invalid"
            )
        }
        try upsert(
            account: "rembrane.account-id",
            data: Data(enrollment.accountID.utf8)
        )
        try upsert(
            account: "rembrane.device-id",
            data: Data(enrollment.deviceID.utf8)
        )
        try upsert(
            account: "rembrane.signing-secret",
            data: enrollment.signingSecret
        )
    }

    /// Removes all enrollment items for this service and optional access
    /// group. Missing items are treated as already revoked.
    public func remove() throws {
        for account in [
            "rembrane.account-id",
            "rembrane.device-id",
            "rembrane.signing-secret",
        ] {
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
        var query = baseQuery(account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              !data.isEmpty else {
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
