# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY version.txt ./

RUN cargo build --release --locked

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 appuser && useradd -r -g appuser -u 1000 appuser
RUN mkdir -p /app /data /config && chown -R appuser:appuser /app /data /config

COPY --from=builder --chown=appuser:appuser /src/target/release/gofile-dl /usr/local/bin/gofile-dl
COPY --chown=appuser:appuser config.yml version.txt ./
COPY --chown=appuser:appuser templates ./templates

ENV PORT=2355 \
    HOST="0.0.0.0" \
    BASE_DIR="/data" \
    CONFIG_DIR="/config"

EXPOSE 2355

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:${PORT}/health || exit 1

CMD ["gofile-dl", "serve"]
