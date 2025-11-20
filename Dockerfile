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

# Create non-root user
RUN useradd -m -u 1000 probeproxy

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/probe-proxy /app/probe-proxy

# Change ownership
RUN chown -R probeproxy:probeproxy /app

# Switch to non-root user
USER probeproxy

# Expose port 443
EXPOSE 443

# Run the proxy
CMD ["/app/probe-proxy"]
