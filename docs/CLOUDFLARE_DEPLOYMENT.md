# Cloudflare Tunnel deployment

This deployment keeps Rembrane, its SQLite database, OAuth credentials, and
workspace encryption keys on the operator-controlled host. Cloudflare Tunnel
provides outbound-only connectivity to the public hostname; the Rembrane
origin remains bound to loopback on the host and is reachable by `cloudflared`
only through the private Compose network.

Cloudflare is a transport and edge-security option, not the canonical memory
store or encryption-key owner. Remote MCP must still validate OAuth access
tokens, derive identity from verified claims, enforce canonical workspace
authorization, and record disclosures.

## Prerequisites

1. Create a remotely managed Cloudflare Tunnel.
2. Configure its public hostname to use `http://rembrane:8787` as the service.
3. Protect the hostname with TLS and an OAuth-capable authorization server.
4. Keep the tunnel token and every Rembrane secret outside tracked files.
5. Pin `CLOUDFLARED_IMAGE` to a reviewed immutable digest in production.

## Start

Set the ordinary variables documented in `.env.example`, plus:

```text
CLOUDFLARE_TUNNEL_TOKEN=<secret tunnel token>
CLOUDFLARED_IMAGE=cloudflare/cloudflared@sha256:<reviewed digest>
```

Then run:

```sh
docker compose -f compose.yaml -f compose.cloudflare.yaml up --build -d
```

The base Compose file publishes only `127.0.0.1:8787`; it does not expose the
origin on a public host interface. The tunnel container has no Linux
capabilities, uses a read-only root filesystem, and receives no Rembrane
database volume or workspace key variables.

## Required edge and origin controls

- Do not use a Cloudflare bypass rule that permits unauthenticated `/mcp`.
- Forward the original `Authorization` and `Origin` headers unchanged.
- Do not place bearer tokens in URLs, query strings, cookies, logs, or tunnel
  configuration.
- Configure the Rembrane OAuth resource audience to the exact public MCP URL.
- Restrict trusted browser origins explicitly.
- Keep origin-side OAuth verification enabled even when Cloudflare Access is
  also enabled.
- Rate-limit malformed and unauthenticated traffic at the edge and origin.

## Rotation and removal

Rotate the Tunnel token in Cloudflare and restart only the `cloudflared`
service. Removing the tunnel does not delete the local database or encryption
keys. To disconnect public access immediately:

```sh
docker compose -f compose.yaml -f compose.cloudflare.yaml stop cloudflared
```
