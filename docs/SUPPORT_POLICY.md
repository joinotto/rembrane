# Support and Compatibility Policy

Central Memory is designed to integrate with open and cooperative AI tools. It does not bypass platform security, intercept closed conversations, or promise compatibility where a tool exposes no supported integration surface.

## Supported integration classes

| Class | Support level | Requirements |
|---|---|---|
| Native | Full | The tool implements the Memory Provider Protocol or an official SDK |
| MCP or tool | Full within host limits | The host supports MCP, tools, skills, plugins, or extensions |
| API or webhook | Full within API limits | The operator provides a documented API and required authorization |
| User-controlled gateway | Full for routed conversations | The user or workspace controls the bot and channel endpoint |
| Share or context card | Assisted | The application provides an extension, share sheet, or paste surface |
| Import or export | Best effort | The platform provides a documented portable format |

## Explicitly unsupported

- Silent capture of arbitrary iMessage conversations.
- Interception of conversations with another company's WhatsApp bot.
- Injection into closed assistants without vendor cooperation.
- Scraping private application databases as a standard integration.
- Bypassing operating-system permissions, platform security, or end-to-end encryption.
- Sending an entire memory store to an agent for an ordinary request.
- Automatically storing every conversation without clear user control.
- Depending on undocumented automation as a stable, supported feature.

Experimental community adapters may exist, but they must be clearly labeled and isolated from the supported core.

## Compatibility labels

Every official integration must publish one label:

```text
Native
MCP/Tool
API/Webhook
Gateway
Manual
Experimental
Unsupported
```

The integration registry must also disclose:

- Read and write permissions.
- Supported deployment modes.
- Whether plaintext leaves the user's controlled environment.
- Whether deletion and revocation propagate.
- Last tested tool version and date.
- Known platform restrictions.

## iMessage

Official support is limited to public, user-controlled surfaces:

- Share extensions.
- Context cards.
- User-confirmed capture and insertion.
- An iMessage application extension where permitted by Apple's public APIs.

Background interception, silent injection into an existing bot conversation, and private Messages database scraping are not supported product features.

## WhatsApp

Official support includes:

- Bots operated through a user-controlled WhatsApp Business account.
- Vendors that integrate the protocol or SDK.
- Documented webhook and API flows.
- Explicitly initiated sharing or import.

The project does not claim access to direct conversations between a user and an unrelated closed WhatsApp bot.

## Security boundary

Channel encryption does not grant Central Memory access to channel contents. Data enters the framework only through an authorized adapter, explicit user action, or documented import. Once context is disclosed to an external agent, that copy is also governed by the agent provider's policies.

## Maintenance rule

Core maintainers may decline or remove an integration when it:

- Requires bypassing a platform's security controls.
- Cannot preserve tenant isolation or user consent.
- Causes material data-loss or disclosure risk.
- Depends primarily on unstable undocumented behavior.
- Cannot support reliable revocation or transparent permission reporting.
