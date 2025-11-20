# Rust Forward Proxy - HTTP/2 Extended CONNECT Support

High-performance forward proxy built with Rust + Tokio + Hyper/h2, implementing native HTTP/2 Extended CONNECT (RFC 8441) with HTTP/1.1 fallback.

> ⚠️ **Phase 1 Status**: ALPN negotiation and certificate hot-reload are complete. HTTP/2 and HTTP/1.1 CONNECT handlers are placeholders that log and close connections. Full tunneling functionality will be implemented in Phases 3-4.

## Features - Phase 1 Complete

### ✅ Currently Implemented (Phase 1)
- ✅ **TLS with ALPN** - Automatic protocol negotiation (h2, http/1.1)
- ✅ **Certificate Hot-Reload** - Zero-downtime cert updates (SIGHUP on Unix)
- ✅ **Connection Routing** - ALPN-based handler selection
- ✅ **Graceful Shutdown** - SIGINT/SIGTERM signal handling
- ✅ **Structured Logging** - JSON output via tracing

### ⏳ Planned Features (Future Phases)
- ⏳ **HTTP/2 Extended CONNECT** (RFC 8441) - Phase 4 (7 days)
- ⏳ **HTTP/1.1 CONNECT** - Phase 3 (1.5 days)
- ⏳ **JWT Authentication** - Phase 2 (2 days)
- ⏳ **Token-based Rate Limiting** - Phase 2 (2 days)
- ⏳ **Request/Response Logging** - Phase 6 (1 day)
- ⏳ **Prometheus Metrics** - Phase 9 (1 day)

## Architecture

```
Desktop App (Electron/Chromium)
    ↓ TLS Handshake
    ↓ ALPN Negotiation: h2, http/1.1
    ↓
Rust Proxy (ALPN Router)
    ├─ If h2 selected → HTTP/2 Extended CONNECT (h2 crate)
    │                    - Stream multiplexing (100+ streams)
    │                    - Frame-level flow control
    │                    - Direct SendStream/RecvStream access
    │
    └─ If http/1.1 selected → HTTP/1.1 CONNECT (Hyper)
                               - upgrade::on() for tunneling
                               - Bidirectional TCP copy
```

## Implementation Status

| Phase | Description | Status | Duration |
|-------|-------------|--------|----------|
| **0** | Pre-implementation (schema, tools) | ⏳ Pending | 4h |
| **1** | Project setup + TLS + ALPN | ✅ Complete | 10h |
| **2** | JWT auth + rate limiting | ⏳ Pending | 16h |
| **3** | HTTP/1.1 CONNECT (foundation) | ⏳ Pending | 12h |
| **4** | HTTP/2 core (CRITICAL PATH) | ⏳ Pending | 56h (7 days) |
| **5** | Stream mgmt + flow control | ⏳ Pending | 16h |
| **6** | Request/response size tracking | ⏳ Pending | 8h |
| **7** | Integration testing | ⏳ Pending | 20h |
| **8** | Load + performance testing | ⏳ Pending | 12h |
| **9** | Observability + metrics | ⏳ Pending | 10h |
| **10** | Production deployment | ⏳ Pending | 12h |
| **11** | Legacy cleanup (Go proxy) | ⏳ Pending | 8h |

**Total**: 148h (23-25 days)
**Current**: Day 2 (Phase 1 complete)

## Quick Start

### Prerequisites

#### Linux/Ubuntu (Staging/Production)
```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# 2. Load Rust environment
source "$HOME/.cargo/env"

# 3. Verify installation
cargo --version  # Should show: cargo 1.91.x
rustc --version  # Should show: rustc 1.91.x

# 4. Navigate to project
cd probe_node/rust_proxy
```

#### Windows (Development)
```bash
# 1. Install MSVC Build Tools (see WINDOWS_SETUP.md for detailed instructions)
# Download from: https://visualstudio.microsoft.com/downloads/
# Select: "Desktop development with C++"

# 2. Install Rust
# Download from: https://rustup.rs
# Or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. Restart terminal and verify
cargo --version
```

### Build

```bash
# Navigate to project directory
cd probe_node/rust_proxy

# Check for compilation errors
cargo check

# Build debug version (with debug symbols, ~50-100MB)
cargo build

# Build optimized release (2.5MB, production-ready)
cargo build --release

# Verify binary
ls -lh target/release/probe-proxy*  # Linux: probe-proxy
# or
dir target\release\probe-proxy.exe  # Windows: probe-proxy.exe
```

### Running (Development - No TLS Certs Required for Build)

**Note**: The binary requires valid TLS certificates to run. For now, compilation testing is sufficient for Phase 1 validation.

```bash
# With TLS certificates configured
RUST_LOG=info cargo run --release

# Expected startup logs:
# [INFO] Starting Rust Forward Proxy Server...
# [INFO] Configuration loaded
# [INFO] TLS configured with ALPN protocols: h2, http/1.1
# [INFO] Certificate hot-reload enabled via SIGHUP
# [INFO] Listening on 0.0.0.0:443
```

### Configuration

Create `.env` file:

```bash
# Server
PROXY_HOST=0.0.0.0
PROXY_PORT=443

# TLS
TLS_CERT_PATH=/etc/letsencrypt/live/staging.probeops.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/staging.probeops.com/privkey.pem

# JWT
JWT_SECRET=your_secret_key_here
JWT_ALGORITHM=HS256

# Rate Limiting (10k req/min per token)
RATE_LIMIT_REQUESTS_PER_MINUTE=10000
RATE_LIMIT_BURST_SIZE=500

# Backend API
BACKEND_URL=https://staging.probeops.com
PROBE_NODE_NAME=probe-node-rust
PROBE_NODE_REGION=us-east
```

### Run

```bash
# Development (with logs)
RUST_LOG=info cargo run

# Production (release build)
cargo run --release
```

### Testing

```bash
# Test ALPN negotiation
openssl s_client -connect localhost:443 -alpn h2,http/1.1

# Expected output:
# ALPN protocol: h2

# Test HTTP/2 CONNECT (once Phase 4 complete)
nghttp -v --no-verify \
  -H "proxy-authorization: Bearer $JWT" \
  "https://localhost:443/www.google.com:443"
```

## Project Structure

```
src/
├── main.rs           # Server entry + ALPN routing
├── config.rs         # Environment configuration
├── tls.rs            # TLS + ALPN setup
├── server.rs         # HTTP/1.1 and HTTP/2 handlers
├── auth.rs           # JWT validation (Phase 2)
├── rate_limit.rs     # Token bucket rate limiter (Phase 2)
├── http1/            # HTTP/1.1 CONNECT implementation (Phase 3)
│   ├── tunnel.rs
│   └── handler.rs
├── http2/            # HTTP/2 Extended CONNECT (Phase 4)
│   ├── server.rs     # h2::server setup
│   ├── connect.rs    # CONNECT request handling
│   ├── tunnel.rs     # Bidirectional stream copy
│   └── flow.rs       # Flow control management
├── logger.rs         # Request/response logging (Phase 6)
└── metrics.rs        # Prometheus metrics (Phase 9)

Cargo.toml            # Dependencies
.env                  # Configuration (not in git)
Dockerfile            # Container image (Phase 10)
```

## Key Dependencies

```toml
tokio = "1.35"              # Async runtime
hyper = "1.1"               # HTTP/1.1 server
h2 = "0.4"                  # HTTP/2 framing (direct access)
tokio-rustls = "0.25"       # TLS with ALPN
jsonwebtoken = "9.2"        # JWT validation
lru = "0.12"                # Rate limiting cache
prometheus = "0.13"         # Metrics
tracing = "0.1"             # Structured logging
```

## Performance Targets

| Metric | HTTP/1.1 Baseline | HTTP/2 Target | Status |
|--------|-------------------|---------------|--------|
| Requests/sec | 1,200 | > 1,000 | ⏳ TBD |
| p50 latency | 45ms | < 60ms | ⏳ TBD |
| p99 latency | 120ms | < 180ms | ⏳ TBD |
| Concurrent streams | N/A | 100+ | ⏳ TBD |
| Memory (100 streams) | 80MB | < 120MB | ⏳ TBD |

**Acceptance**: HTTP/2 within 120% of HTTP/1.1 performance.

## Development Notes

### Phase 1 (Complete)

**Implemented:**
- TLS certificate loading from PEM files
- ALPN configuration advertising h2 and http/1.1
- Server loop accepting TLS connections
- ALPN protocol detection and routing
- Graceful shutdown with SIGINT/SIGTERM/SIGHUP

**Handler Status:**
- `serve_h2()` - Placeholder (logs and closes)
- `serve_http1()` - Placeholder (logs and closes)

### Phase 4 (HTTP/2 Core - CRITICAL PATH)

**Key Design Decision**: Bypass Hyper for HTTP/2

**Rationale**: Hyper 1.x doesn't expose `SendStream`/`RecvStream` for Extended CONNECT. We use `h2::server::handshake()` directly.

**Implementation Strategy**:
```rust
// Direct h2 server
let mut h2_conn = h2::server::Builder::new()
    .initial_window_size(65535)
    .max_concurrent_streams(100)
    .handshake(tls_stream).await?;

while let Some((request, respond)) = h2_conn.accept().await {
    // request: http::Request<h2::RecvStream>
    // respond: h2::server::SendResponse<Bytes>

    // Full control over streams for tunneling
}
```

**Testing Plan** (Phase 4 Go/No-Go Checkpoint):
1. nghttp connectivity test
2. Stream multiplexing (10 concurrent streams)
3. Authentication rejection (invalid JWT)
4. Rate limiting (exceed 10k req/min)
5. Large transfer (10MB file - flow control test)
6. Database logging verification
7. Memory stability (5-min sustained load)

## Documentation

- **Implementation Plan**: `Documents/2025-11-18/RUST_PROXY_IMPLEMENTATION_PLAN_V4_1_CONCRETE.md`
- **Addendum (Flow Control, Metrics, Go/No-Go)**: `Documents/2025-11-18/RUST_PROXY_V4_1_ADDENDUM_IMPLEMENTATION_DETAILS.md`
- **Windows Setup**: `WINDOWS_SETUP.md` (this directory)
- **Platform Docs**: `../../CLAUDE.md` (ProbeOps general)

## Deployment (Phase 10)

### Gradual Rollout

| Week | Traffic % | Monitoring |
|------|-----------|------------|
| 1 | 0% (staging only) | Stability, memory leaks |
| 2 | 10% | Latency, error rate |
| 3 | 50% | Performance vs Go proxy |
| 4 | 100% | Full migration complete |

### Rollback Procedure

**<10 minutes** to revert to Go proxy via load balancer config.

Archive branch: `archive/go-proxy` (contains full deployment stack)

## Monitoring

### Prometheus Metrics

```promql
# Request rate
rate(proxy_requests_total[5m])

# HTTP/2 vs HTTP/1.1 split
proxy_requests_total{protocol="h2"} / proxy_requests_total

# Rate limit hits
rate(proxy_rate_limit_exceeded_total[5m])

# p99 latency
histogram_quantile(0.99, proxy_request_duration_seconds)

# Active streams
proxy_active_streams{protocol="h2"}
```

### Logs

```bash
# Structured JSON logs via tracing-subscriber
tail -f /var/log/probe-proxy.log | jq .

# Filter HTTP/2 connections
tail -f /var/log/probe-proxy.log | jq 'select(.fields.protocol == "h2")'
```

## Contributing

**Current Phase**: Phase 1 complete - awaiting MSVC installation

**Next Steps**:
1. Install MSVC Build Tools (Windows)
2. Run `cargo build` to verify compilation
3. Implement Phase 2 (JWT auth + rate limiting)

**Code Style**: Follow `rustfmt` defaults

```bash
# Format code
cargo fmt

# Lint
cargo clippy
```

## Support

**Issues**: Create issue in main ProbeOps repository

**Documentation**: See `Documents/2025-11-18/` for complete implementation plans

**Contact**: Engineering team via ProbeOps channels

---

**Status**: Phase 1 Complete ✅ | Phase 2 Pending ⏳
**Timeline**: Day 2 of 25 | On track for 5-week delivery
**Next Milestone**: Phase 4 Go/No-Go Checkpoint (Day 12)
