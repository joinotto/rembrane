# Rembrane Swift SDK

Dependency-free Swift client for Rembrane REST APIs and explicit mobile-share
flows. It supports macOS 13+, iOS 16+, injected async transports, and a
redirect-rejecting ephemeral `URLSession` transport.

> Rembrane is pre-alpha. Pin revisions and review protocol changes before
> upgrading.

## Client

```swift
import Foundation
import Rembrane

let memory = try RembraneClient(
    baseURL: URL(string: ProcessInfo.processInfo.environment["REMBRANE_API_URL"]!)!,
    token: ProcessInfo.processInfo.environment["REMBRANE_API_TOKEN"]!,
    transport: URLSessionRembraneTransport()
)
```

Production endpoints require HTTPS. Plain HTTP is accepted only for explicit
loopback development endpoints. Keep bearer tokens in Keychain or another
platform-protected credential store rather than application source.

## Portable export

```swift
let archive = try await memory.exportPortableData(
    workspaceID: "workspace_personal",
    subjectID: "principal_hippo",
    format: .jsonl
)

try archive.body.write(
    to: privateDestination,
    options: [.atomic, .completeFileProtection]
)
```

JSONL and Markdown exports are subject-scoped. Graph JSON covers the workspace
graph and requires an owner or admin. Every portable export is plaintext; use
an application-private directory with platform file protection, or use an
encrypted Rembrane backup for recovery and opaque transfer.

## Portable import

```swift
let jsonl = try Data(contentsOf: privateSource)
let result = try await memory.importPortableMemories(
    workspaceID: "workspace_personal",
    subjectID: "principal_hippo",
    expectedPreviousSequence: 42,
    jsonl: jsonl
)
```

Imports are limited to 64 MiB, validated atomically by the server, and admitted
only as reviewable proposals. The expected previous sequence rejects writes
against stale workspace state.

## Verify

From the repository root:

```text
./scripts/test-swift-sdk.sh
```
