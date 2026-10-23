# ADR 0004: Honest integration tiers

- Status: Accepted
- Date: 2026-10-23

## Context

Some AI tools expose MCP, APIs, plugins, webhooks, or SDKs. Others are closed applications or messaging contacts. Being reachable through WhatsApp or iMessage does not authorize Rembrane to intercept or inject into those conversations.

## Decision

Every integration is labeled as one of:

- Native
- MCP or tool
- API or webhook
- User-controlled gateway
- Manual share or import
- Experimental
- Unsupported

Official adapters must use documented, authorized platform surfaces. Undocumented scraping or automation is not part of the supported core.

The integration registry records permissions, plaintext exposure, deletion support, deployment support, tested versions, and limitations.

## Consequences

- Rembrane cannot claim compatibility with every closed bot.
- Vendor cooperation remains the preferred path.
- Share sheets, context cards, and imports provide explicit fallback experiences.
- Community experiments are isolated and clearly labeled.
