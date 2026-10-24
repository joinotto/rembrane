# Rembrane iOS Share Extension reference

This reference controller accepts exactly one piece of text that the user
explicitly shares through the iOS share sheet. It does not read the Messages
database, monitor iMessage, capture content in the background, or inject
content into unrelated conversations.

## Integrate

1. Add an iOS Share Extension target in Xcode with iOS 16 or later.
2. Add the local or published `Rembrane` Swift package to the extension target.
3. Copy `ShareViewController.swift` into that target.
4. Set `RembraneGatewayURL` in the extension `Info.plist` to the HTTPS mobile
   share gateway. Loopback HTTP is accepted only for simulator development.
5. Provision these generic-password items into a Keychain access group shared
   by the containing app and extension:

   - service `org.rembrane.mobile-share`, account `rembrane.account-id`;
   - service `org.rembrane.mobile-share`, account `rembrane.device-id`;
   - service `org.rembrane.mobile-share`, account `rembrane.signing-secret`.

6. Give both targets the same Keychain Sharing entitlement. If the deployment
   uses an explicit access group, set the non-secret
   `RembraneKeychainAccessGroup` `Info.plist` value. The shared SDK enrollment
   store applies it to every lookup.
7. Restrict the extension activation rule to text. Do not enable broad file,
   image, web-page, or unlimited attachment activation unless those formats
   receive separate bounded parsers.
8. Enroll the exact account/device pair with `rembrane channel
   bind-mobile-share` before testing.

The signing secret and binding lookup secret are distinct values. The lookup
secret remains on the gateway/operator side; only the signing secret is
provisioned to the device Keychain. Never store either secret in source,
`Info.plist`, `UserDefaults`, app logs, crash metadata, or canonical memory.
The containing companion app can call
`KeychainMobileShareEnrollmentStore.save(_:)` during an explicit enrollment
flow and `remove()` during device revocation. Stored items use
`WhenUnlockedThisDeviceOnly` accessibility. Generate a new secret on the
device with `KeychainMobileShareEnrollmentStore.generateSigningSecret()`
rather than transporting one through logs, pasteboards, or shell commands.

The controller deliberately cancels when more than one text provider is
present. Product UI may show a confirmation screen before submission, but
must not silently broaden the selected content or retry indefinitely after the
user dismisses the extension.
