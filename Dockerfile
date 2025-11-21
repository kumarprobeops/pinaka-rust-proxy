# Multi-stage build for Rust Forward Proxy
# Stage 1: Build the binary
FROM rust:1.91-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Use separate target directory to avoid conflicts with host builds
ENV CARGO_TARGET_DIR=/build/docker-target

# Copy Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY tests ./tests

# Build release binary
RUN cargo build --release

# Stage 2: Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies and libcap2-bin for setcap
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -u 1000 -s /bin/false probeproxy

WORKDIR /app

# Copy binary from builder (using docker-target path)
COPY --from=builder /build/docker-target/release/probe-proxy /app/probe-proxy

# Change ownership to non-root user BEFORE setting capabilities
RUN chown probeproxy:probeproxy /app/probe-proxy

# Set capabilities to allow binding to privileged ports (< 1024) as non-root
# This must be done AFTER chown to preserve capabilities
RUN setcap 'cap_net_bind_service=+ep' /app/probe-proxy

# Switch to non-root user
USER probeproxy

# Expose port 443
EXPOSE 443

# Run the proxy as non-root with CAP_NET_BIND_SERVICE
CMD ["/app/probe-proxy"]
