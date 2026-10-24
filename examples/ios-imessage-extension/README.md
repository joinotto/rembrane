# Rembrane iMessage app extension reference

This public-API-only `MSMessagesAppViewController` lets a user paste or type
text, review it, confirm it, and submit it to the narrow signed mobile-share
gateway.

It cannot read the current conversation, Messages history, participants,
composer contents, attachments, or incoming messages. It does not run a
background listener and does not silently insert content into a conversation.

## Integrate

1. Add an iMessage App Extension target in Xcode with iOS 16 or later.
2. Add the `Rembrane` Swift package to the extension target.
3. Copy `MessagesViewController.swift` into the target and set it as the
   principal Messages view controller.
4. Set `RembraneGatewayURL` in the extension `Info.plist` to the deployment's
   HTTPS mobile-share gateway.
5. Provision the same Keychain service/accounts and Keychain Sharing
   entitlement documented by the iOS Share Extension reference. Set the
   optional non-secret `RembraneKeychainAccessGroup` `Info.plist` value when
   the containing app and extension use an explicit shared access group.
6. Enroll the exact opaque account/device pair with `rembrane channel
   bind-mobile-share`.

The extension intentionally requires a second confirmation after text entry.
Do not replace that flow with transcript scraping, accessibility automation,
private frameworks, automatic send behavior, or hidden background capture.
