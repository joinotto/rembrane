# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder
WORKDIR /source

COPY . .
RUN cargo build --release \
    --package rembrane-api \
    --package rembrane-channel-worker \
    --package rembrane-cli \
    --package rembrane-graph-worker \
    --package rembrane-mcp \
    --package rembrane-mobile-share-gateway \
    --package rembrane-whatsapp-gateway

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 rembrane \
    && useradd --system --uid 10001 --gid rembrane \
        --home-dir /var/lib/rembrane rembrane

COPY --from=builder /source/target/release/rembrane /usr/local/bin/rembrane
COPY --from=builder /source/target/release/rembrane-api \
    /usr/local/bin/rembrane-api
COPY --from=builder /source/target/release/rembrane-channel-worker \
    /usr/local/bin/rembrane-channel-worker
COPY --from=builder /source/target/release/rembrane-mcp \
    /usr/local/bin/rembrane-mcp
COPY --from=builder /source/target/release/rembrane-graph-worker \
    /usr/local/bin/rembrane-graph-worker
COPY --from=builder /source/target/release/rembrane-mobile-share-gateway \
    /usr/local/bin/rembrane-mobile-share-gateway
COPY --from=builder /source/target/release/rembrane-whatsapp-gateway \
    /usr/local/bin/rembrane-whatsapp-gateway
COPY --chmod=755 docker/entrypoint.sh /usr/local/bin/rembrane-entrypoint

ENV REMBRANE_DATABASE=/var/lib/rembrane/rembrane.db
VOLUME ["/var/lib/rembrane"]
EXPOSE 8787
EXPOSE 8790
EXPOSE 8791

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD rembrane doctor \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" || exit 1

ENTRYPOINT ["rembrane-entrypoint"]
CMD ["rembrane-api"]
