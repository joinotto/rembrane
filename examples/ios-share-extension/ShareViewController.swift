import Foundation
import Rembrane
import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Task { @MainActor in
            do {
                let text = try await selectedPlainText()
                let configuration = try ShareConfiguration.load()
                let signer = try CryptoKitMobileShareSigner(
                    secret: configuration.signingSecret
                )
                let client = try RembraneMobileShareClient(
                    baseURL: configuration.gatewayURL,
                    transport: URLSessionRembraneTransport(),
                    signer: signer
                )
                let coordinator = try RembraneExplicitShareCoordinator(
                    accountID: configuration.accountID,
                    deviceID: configuration.deviceID,
                    submitter: client
                )
                try await coordinator.shareSelectedText(text)
                extensionContext?.completeRequest(returningItems: nil)
            } catch {
                extensionContext?.cancelRequest(withError: error)
            }
        }
    }

    private func selectedPlainText() async throws -> String {
        let providers = (extensionContext?.inputItems as? [NSExtensionItem] ?? [])
            .flatMap { $0.attachments ?? [] }
            .filter { $0.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) }
        guard providers.count == 1, let provider = providers.first else {
            throw ShareExtensionError.invalidSelection
        }
        let item = try await provider.loadItem(
            forTypeIdentifier: UTType.plainText.identifier
        )
        if let text = item as? String {
            return text
        }
        if let data = item as? Data,
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        throw ShareExtensionError.invalidSelection
    }
}

private struct ShareConfiguration {
    let gatewayURL: URL
    let accountID: String
    let deviceID: String
    let signingSecret: Data

    static func load() throws -> Self {
        guard let rawURL = Bundle.main.object(
            forInfoDictionaryKey: "RembraneGatewayURL"
        ) as? String,
              let gatewayURL = URL(string: rawURL) else {
            throw ShareExtensionError.invalidConfiguration
        }
        let accessGroup = Bundle.main.object(
            forInfoDictionaryKey: "RembraneKeychainAccessGroup"
        ) as? String
        let enrollment = try KeychainMobileShareEnrollmentStore(
            accessGroup: accessGroup
        ).load()
        return Self(
            gatewayURL: gatewayURL,
            accountID: enrollment.accountID,
            deviceID: enrollment.deviceID,
            signingSecret: enrollment.signingSecret
        )
    }
}

private enum ShareExtensionError: Error {
    case invalidSelection
    case invalidConfiguration
}
