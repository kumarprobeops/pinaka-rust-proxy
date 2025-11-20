# Multi-stage build for Rust Forward Proxy
# Stage 1: Build the binary
FROM rust:1.91-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build release binary
RUN cargo build --release

# Stage 2: Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/probe-proxy /app/probe-proxy

# Make binary executable
RUN chmod +x /app/probe-proxy

# Expose port 443
EXPOSE 443

# Run the proxy as root (Phase 1)
# TODO Phase 2: Add CAP_NET_BIND_SERVICE and run as non-root user
CMD ["/app/probe-proxy"]
