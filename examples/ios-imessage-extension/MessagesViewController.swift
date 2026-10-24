import Foundation
import Messages
import Rembrane
import Security
import UIKit

@MainActor
final class MessagesViewController: MSMessagesAppViewController {
    private let textView = UITextView()
    private let saveButton = UIButton(type: .system)
    private let statusLabel = UILabel()
    private var isSubmitting = false

    override func viewDidLoad() {
        super.viewDidLoad()

        textView.font = .preferredFont(forTextStyle: .body)
        textView.layer.borderColor = UIColor.separator.cgColor
        textView.layer.borderWidth = 1
        textView.layer.cornerRadius = 8
        textView.text = ""
        textView.accessibilityLabel = "Text to add to Rembrane"

        saveButton.setTitle("Add to Rembrane", for: .normal)
        saveButton.addTarget(self, action: #selector(confirmShare), for: .touchUpInside)

        statusLabel.font = .preferredFont(forTextStyle: .footnote)
        statusLabel.numberOfLines = 0
        statusLabel.text = "Paste or type only the text you want to save."

        let stack = UIStackView(arrangedSubviews: [textView, saveButton, statusLabel])
        stack.axis = .vertical
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
            stack.topAnchor.constraint(equalTo: view.layoutMarginsGuide.topAnchor),
            stack.bottomAnchor.constraint(
                lessThanOrEqualTo: view.layoutMarginsGuide.bottomAnchor
            ),
            textView.heightAnchor.constraint(greaterThanOrEqualToConstant: 120),
        ])
    }

    @objc
    private func confirmShare() {
        guard !isSubmitting else { return }
        let text = textView.text ?? ""
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            statusLabel.text = "Enter text before continuing."
            return
        }

        let alert = UIAlertController(
            title: "Add this text to Rembrane?",
            message: "Only the text shown in this extension will be submitted.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Add", style: .default) { [weak self] _ in
            self?.submit(text)
        })
        present(alert, animated: true)
    }

    private func submit(_ text: String) {
        isSubmitting = true
        saveButton.isEnabled = false
        statusLabel.text = "Submitting…"

        Task { @MainActor in
            defer {
                isSubmitting = false
                saveButton.isEnabled = true
            }
            do {
                let configuration = try MessagesShareConfiguration.load()
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
                textView.text = ""
                statusLabel.text = "Added to Rembrane."
            } catch {
                statusLabel.text = "Could not add the text. Try again after checking setup."
            }
        }
    }
}

private struct MessagesShareConfiguration {
    let gatewayURL: URL
    let accountID: String
    let deviceID: String
    let signingSecret: Data

    static func load() throws -> Self {
        guard let rawURL = Bundle.main.object(
            forInfoDictionaryKey: "RembraneGatewayURL"
        ) as? String,
              let gatewayURL = URL(string: rawURL) else {
            throw MessagesExtensionError.invalidConfiguration
        }
        return try Self(
            gatewayURL: gatewayURL,
            accountID: MessagesKeychain.readUTF8(account: "rembrane.account-id"),
            deviceID: MessagesKeychain.readUTF8(account: "rembrane.device-id"),
            signingSecret: MessagesKeychain.readData(account: "rembrane.signing-secret")
        )
    }
}

private enum MessagesExtensionError: Error {
    case invalidConfiguration
    case keychainItemUnavailable
}

private enum MessagesKeychain {
    static func readUTF8(account: String) throws -> String {
        let data = try readData(account: account)
        guard let value = String(data: data, encoding: .utf8), !value.isEmpty else {
            throw MessagesExtensionError.keychainItemUnavailable
        }
        return value
    }

    static func readData(account: String) throws -> Data {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.rembrane.mobile-share",
            kSecAttrAccount: account,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              !data.isEmpty else {
            throw MessagesExtensionError.keychainItemUnavailable
        }
        return data
    }
}
