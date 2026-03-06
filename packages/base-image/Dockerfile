# Container IDS Base Image - Alpine Linux (Lightweight)
# Enterprises use this as their base: FROM your-registry/container-ids-base:latest

# Multi-stage build for smaller final image
FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    linux-headers \
    clang \
    llvm \
    libbpf-dev

# Build the agent
WORKDIR /build
COPY packages/agent /build

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -a -installsuffix cgo \
    -o agent \
    ./cmd/agent

# Final stage - minimal Alpine image
FROM alpine:3.23

LABEL maintainer="github.com/arman-develops"
LABEL description="Container IDS monitoring base image - Alpine Linux"
LABEL version="1.0.0"

# Install only runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    bash \
    procps \
    net-tools \
    iproute2 \
    iptables \
    # eBPF runtime
    libbpf \
    # Utilities
    vim \
    less \
    jq \
    && rm -rf /var/cache/apk/*

# Create directories
RUN mkdir -p /opt/container-ids \
    /etc/container-ids \
    /var/log/container-ids

# Copy agent binary from builder
COPY --from=builder /build/agent /opt/container-ids/agent

# Copy configuration and scripts
COPY packages/base-image/config/agent.yaml /etc/container-ids/agent.yaml
COPY packages/base-image/entrypoint.sh /opt/container-ids/entrypoint.sh
RUN chmod +x /opt/container-ids/entrypoint.sh

# Create non-root user
RUN adduser -D -u 1000 -s /bin/bash appuser

# Agent runs on port 8443 for connection service
EXPOSE 8443

# Environment variables (can be overridden)
ENV AGENT_API_KEY="3a8f6c52-9f44-4b78-b3c6-2a7e9d4c1f0b" \
    RABBITMQ_URL="amqp://guest:guest@platform-rabbitmq:5672/" \
    AGENT_LOG_LEVEL="info" \
    CONNECTION_SERVICE_ENABLED="true" \
    CONNECTION_SERVICE_PORT="8443"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8443/health || exit 1

# Use the entrypoint script
ENTRYPOINT ["/opt/container-ids/entrypoint.sh"]

# Default command (can be overridden)
CMD ["/bin/sh"]