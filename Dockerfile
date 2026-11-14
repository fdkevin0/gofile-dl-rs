# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder
ARG BUILDARCH
ARG TARGETARCH

WORKDIR /src
RUN if [ -n "$TARGETARCH" ] && [ "$BUILDARCH" != "$TARGETARCH" ]; then \
      if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross && \
        rm -rf /var/lib/apt/lists/*; \
      elif [ "$TARGETARCH" = "amd64" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross && \
        rm -rf /var/lib/apt/lists/*; \
      fi; \
    fi

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc

RUN case "$TARGETARCH" in \
      amd64) RUST_TARGET="x86_64-unknown-linux-gnu" ;; \
      arm64) RUST_TARGET="aarch64-unknown-linux-gnu" ;; \
      "")    RUST_TARGET="" ;; \
      *)     echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    if [ -n "$RUST_TARGET" ]; then \
      rustup target add "$RUST_TARGET" && \
      cargo build --release --locked --target "$RUST_TARGET" && \
      cp "target/$RUST_TARGET/release/gofile-dl" /src/gofile-dl; \
    else \
      cargo build --release --locked && \
      cp target/release/gofile-dl /src/gofile-dl; \
    fi

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 appuser && useradd -r -g appuser -u 1000 appuser
RUN mkdir -p /app /data /config && chown -R appuser:appuser /app /data /config

COPY --from=builder --chown=appuser:appuser /src/gofile-dl /usr/local/bin/gofile-dl
COPY --chown=appuser:appuser config.yml ./
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
