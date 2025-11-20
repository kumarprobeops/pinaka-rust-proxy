# Rust Forward Proxy - Implementation Plan V4.1
## HTTP/2 Extended CONNECT with HTTP/1.1 Fallback

**Document Version**: 4.1
**Last Updated**: 2025-11-20
**Status**: Phase 3 Complete ✅ | Phase 4 Ready to Start
**Timeline**: Days 1-10 Complete | 15 days remaining

---

## Executive Summary

Building a high-performance Rust-based forward proxy to replace the existing Go implementation, with native HTTP/2 Extended CONNECT support (RFC 8441) and HTTP/1.1 CONNECT fallback. The proxy uses TLS with ALPN for protocol negotiation, JWT authentication, and per-token rate limiting.

**Key Innovation**: Direct use of `h2` crate for HTTP/2, bypassing Hyper's limitations with Extended CONNECT stream handling.

---

## Implementation Phases - Current Status

### ✅ Phase 1: TLS + ALPN + Hot-Reload (COMPLETE)
**Duration**: Day 1-2 | **Status**: ✅ Complete
**Commit**: `faa6f0e` - Initial commit: Phase 1

**Implemented**:
- ✅ TLS certificate loading from PEM files
- ✅ ALPN configuration (h2, http/1.1)
- ✅ Server loop with TLS accept
- ✅ ALPN protocol detection and routing
- ✅ Certificate hot-reload (SIGHUP signal)
- ✅ Graceful shutdown (SIGINT/SIGTERM)
- ✅ Structured logging with tracing

**Key Files**:
- `src/main.rs` - Server entry point with ALPN routing
- `src/tls.rs` - TLS setup with ALPN and certificate reload
- `src/config.rs` - Environment-based configuration
- `src/reload.rs` - ReloadableTlsAcceptor for hot cert updates

**Validation**:
```bash
openssl s_client -connect localhost:443 -alpn h2,http/1.1
# Output: ALPN protocol: h2
```

---

### ✅ Phase 2: JWT Authentication + Rate Limiting (COMPLETE)
**Duration**: Day 3-6 | **Status**: ✅ Complete
**Commits**:
- `144614d` - Implement Phase 2 - JWT authentication and rate limiting
- `c6d0a2e` - Phase 2.1 - Critical security and reliability improvements
- `5cf4df5` - Phase 2.2 - Engineering feedback implementation
- `f59b0e3` - Phase 2.2 Audit Response

**Implemented**:

#### JWT Authentication (`src/auth.rs`)
- ✅ JWT token validation with jsonwebtoken
- ✅ HS256 algorithm support
- ✅ Region-based access control (allowed_regions)
- ✅ Wildcard region support ["*"] for SuperAdmin
- ✅ Optional issuer/audience validation
- ✅ Token expiration checking
- ✅ Proxy-Authorization header extraction (Bearer scheme)
- ✅ 32+ character secret enforcement
- ✅ Comprehensive test coverage (10 tests)

**JWT Claims Structure**:
```rust
pub struct JwtClaims {
    pub token_id: String,           // Unique token identifier
    pub user_id: i32,                // User ID
    pub allowed_regions: Vec<String>, // ["us-east", "eu-west"] or ["*"]
    pub exp: i64,                    // Expiration timestamp
    pub iat: i64,                    // Issued at timestamp
    pub iss: Option<String>,         // Optional issuer
    pub aud: Option<String>,         // Optional audience
}
```

#### Rate Limiting (`src/rate_limiter.rs`)
- ✅ Token bucket algorithm per token_id
- ✅ Configurable rate (10,000 req/min default)
- ✅ Burst capacity (500 requests)
- ✅ Async-safe with tokio::sync::RwLock
- ✅ Automatic bucket cleanup (TTL-based)
- ✅ Max concurrent tokens limit (10,000)
- ✅ Comprehensive test coverage (12 tests)

**Configuration** (`.env`):
```bash
JWT_SECRET=your_secret_key_minimum_32_chars
JWT_ALGORITHM=HS256
JWT_ISSUER=probeops                    # Optional
JWT_AUDIENCE=forward-proxy             # Optional

RATE_LIMIT_REQUESTS_PER_MINUTE=10000
RATE_LIMIT_BURST_SIZE=500
RATE_LIMIT_BUCKET_TTL_SECONDS=300
RATE_LIMIT_MAX_BUCKETS=10000
```

**Phase 2 Test Results**: 32 tests passing

---

### ✅ Phase 3: HTTP/1.1 CONNECT Handler (COMPLETE)
**Duration**: Day 7-10 | **Status**: ✅ Complete
**Commits**:
- `3bf12f1` - Implement Phase 3 - HTTP/1.1 CONNECT Handler
- `686b9e0` - Address engineering feedback - Critical fixes
- `beb1ae0` - Strengthen CONNECT authority parsing
- `93f3e87` - Add Phase 3 end-to-end integration tests

**Implemented** (`src/server.rs`):

#### CONNECT Handler with Full Validation
- ✅ Hyper-based HTTP/1.1 server with upgrade support
- ✅ JWT authentication integration
- ✅ Rate limiting integration
- ✅ Authority parsing and validation (host:port)
  - Port must be numeric (1-65535)
  - Host cannot be empty
  - IPv6 bracket notation support ([::1]:443)
- ✅ Bidirectional TCP tunneling with tokio::io::copy
- ✅ Comprehensive error handling:
  - 407 Proxy Authentication Required (with Bearer challenge)
  - 400 Bad Request (malformed authority/auth)
  - 403 Forbidden (region not allowed)
  - 429 Too Many Requests (rate limit exceeded)
  - 502 Bad Gateway (upstream connection failure)
  - 503 Service Unavailable (too many tokens)

**Request Flow**:
```
Client → TLS Handshake → ALPN (http/1.1)
       → HTTP/1.1 CONNECT example.com:443
       → Validate Authority (parse_authority)
       → Authenticate JWT (config.jwt_validator)
       → Rate Limit Check (config.rate_limiter)
       → Connect Upstream (tokio::net::TcpStream)
       → Send 200 Connection Established
       → Spawn Bidirectional Tunnel Task
       → Tunnel Data (client ↔ upstream)
```

**Tunnel Implementation**:
```rust
// Bidirectional copy using tokio::io::split
let (mut client_read, mut client_write) = tokio::io::split(client);
let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

let (c_to_u, u_to_c) = tokio::try_join!(client_to_upstream, upstream_to_client)?;
```

**Phase 3 Test Coverage**:
- ✅ Authority parsing (2 tests - 13 cases)
- ✅ Error handlers (2 tests - all error paths)
- ✅ End-to-end CONNECT flow (7 integration tests):
  - Missing authentication (407)
  - Invalid auth format (400)
  - Expired token (407)
  - Wrong region (403)
  - Wildcard region (passes auth)
  - Malformed authorities (400 for 5 cases)
  - Valid auth attempts upstream (200/502)

**Phase 3 Test Results**: 43 tests passing (11 new Phase 3 tests)

**Phase 3 Audit Findings** (All Addressed):
- ✅ Region wildcard now enforced in validator
- ✅ Proxy-Authenticate uses Bearer scheme (RFC 7235)
- ✅ Authority validation with port/host checks
- ✅ Comprehensive integration test coverage

---

### ⏳ Phase 4: HTTP/2 Extended CONNECT (IN PROGRESS)
**Duration**: Day 11-17 (7 days) | **Status**: ⏳ Ready to Start
**Critical Path**: Most complex phase - determines project success

**Goal**: Implement HTTP/2 Extended CONNECT (RFC 8441) using direct `h2` crate for stream access.

#### Why Direct h2 Instead of Hyper?

**Problem**: Hyper 1.x doesn't expose `SendStream`/`RecvStream` for HTTP/2 Extended CONNECT tunneling.

**Solution**: Use `h2::server::handshake()` directly for full control over HTTP/2 streams.

**Trade-offs**:
| Aspect | Hyper | Direct h2 |
|--------|-------|-----------|
| HTTP/2 CONNECT | ❌ Limited | ✅ Full stream access |
| Code complexity | Low | Medium |
| Performance | Good | Excellent |
| Stream control | Limited | Complete |

#### Implementation Plan

**Phase 4.1: h2::server Setup** (Day 11)
```rust
pub async fn serve_h2(
    tls_stream: TlsStream<TcpStream>,
    config: Arc<Config>,
) -> Result<()> {
    // 1. Create h2 server connection
    let mut h2_conn = h2::server::Builder::new()
        .initial_window_size(65535)          // 64KB per stream
        .max_concurrent_streams(100)         // Limit concurrent streams
        .max_frame_size(16384)               // 16KB frame size
        .handshake(tls_stream)
        .await?;

    // 2. Accept and process streams
    while let Some(result) = h2_conn.accept().await {
        let (request, respond) = result?;

        tokio::spawn(async move {
            handle_h2_request(request, respond, config).await
        });
    }

    Ok(())
}
```

**Phase 4.2: CONNECT Request Handling** (Day 12-13)
```rust
async fn handle_h2_request(
    request: Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    config: Arc<Config>,
) -> Result<()> {
    // 1. Validate Extended CONNECT
    if request.method() != Method::CONNECT {
        send_error(&mut respond, StatusCode::METHOD_NOT_ALLOWED).await?;
        return Ok(());
    }

    // 2. Extract and validate authority
    let authority = request.uri().authority()
        .ok_or_else(|| anyhow!("Missing authority"))?;
    let (host, port) = parse_authority(authority.as_str())?;

    // 3. Authenticate JWT
    let claims = config.jwt_validator.validate_request(&request)
        .map_err(|e| handle_auth_error_h2(&mut respond, e))?;

    // 4. Rate limiting
    config.rate_limiter.check_limit(&claims.token_id).await
        .map_err(|e| handle_rate_limit_error_h2(&mut respond, e))?;

    // 5. Connect to upstream
    let upstream = TcpStream::connect(format!("{}:{}", host, port)).await?;

    // 6. Send 200 OK response
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    let mut send_stream = respond.send_response(response, false)?;

    // 7. Get request body stream
    let recv_stream = request.into_body();

    // 8. Start bidirectional tunnel
    tunnel_h2_streams(recv_stream, send_stream, upstream, claims).await?;

    Ok(())
}
```

**Phase 4.3: Bidirectional Stream Tunneling** (Day 14-15)
```rust
async fn tunnel_h2_streams(
    mut recv_stream: h2::RecvStream,      // Client → Proxy
    mut send_stream: h2::SendStream<Bytes>, // Proxy → Client
    upstream: TcpStream,                   // Proxy ↔ Upstream
    claims: JwtClaims,
) -> Result<()> {
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    // Task 1: Client → Upstream
    let client_to_upstream = async {
        while let Some(data) = recv_stream.data().await {
            let data = data?;
            upstream_write.write_all(&data).await?;

            // Release flow control
            let _ = recv_stream.flow_control().release_capacity(data.len());
        }
        upstream_write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };

    // Task 2: Upstream → Client
    let upstream_to_client = async {
        let mut buf = vec![0u8; 16384]; // 16KB buffer
        loop {
            let n = upstream_read.read(&mut buf).await?;
            if n == 0 { break; }

            send_stream.send_data(Bytes::copy_from_slice(&buf[..n]), false).await?;
        }
        send_stream.send_data(Bytes::new(), true).await?; // EOS
        Ok::<_, anyhow::Error>(())
    };

    // Run both tasks concurrently
    tokio::try_join!(client_to_upstream, upstream_to_client)?;

    info!(
        "[H2 CONNECT] Completed {} - user_id={}, token_id={}",
        authority, claims.user_id, claims.token_id
    );

    Ok(())
}
```

**Phase 4.4: Error Handling** (Day 16)
- 407 Proxy Authentication Required (with Bearer challenge)
- 400 Bad Request (malformed requests)
- 403 Forbidden (auth failures)
- 429 Too Many Requests (rate limit)
- 502 Bad Gateway (upstream connection failure)
- 503 Service Unavailable (too many tokens)

**Phase 4.5: Testing** (Day 17)
```bash
# Install nghttp client
sudo apt-get install nghttp2-client

# Test HTTP/2 CONNECT
nghttp -v --no-verify \
  -H "proxy-authorization: Bearer $JWT_TOKEN" \
  "https://localhost:443/www.google.com:443"

# Expected: 200 OK, followed by tunneled HTTPS traffic
```

**Test Cases**:
1. ✅ Basic CONNECT with valid auth
2. ✅ Missing authorization (407)
3. ✅ Expired token (407)
4. ✅ Wrong region (403)
5. ✅ Rate limit exceeded (429)
6. ✅ Malformed authority (400)
7. ✅ Stream multiplexing (10 concurrent streams)
8. ✅ Large transfer (10MB file - flow control)
9. ✅ Upstream connection failure (502)

**Success Criteria**:
- All test cases pass
- No memory leaks after 5-minute sustained load
- Latency within 120% of HTTP/1.1 baseline

---

### ⏳ Phase 5: Stream Management + Flow Control (PENDING)
**Duration**: Day 18-19 (2 days) | **Status**: ⏳ Pending

**Objectives**:
- Implement proper HTTP/2 flow control
- Handle stream errors gracefully
- Add stream timeout handling
- Implement connection-level flow control

**Key Challenges**:
- Avoid flow control deadlocks
- Handle slow readers/writers
- Manage memory with many concurrent streams

---

### ⏳ Phase 6: Request/Response Logging (PENDING)
**Duration**: Day 20 (1 day) | **Status**: ⏳ Pending

**Objectives**:
- Log all proxy requests to backend database
- Track bytes transferred (client→upstream, upstream→client)
- Record connection duration
- Log auth failures and rate limit events

**Database Schema** (backend already has this):
```sql
CREATE TABLE proxy_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_id VARCHAR(255) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL, -- 'http/1.1' or 'h2'
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    duration_ms INTEGER,
    status_code INTEGER,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

### ⏳ Phase 7: Integration Testing (PENDING)
**Duration**: Day 21-22 (2 days) | **Status**: ⏳ Pending

**Test Scenarios**:
1. HTTP/1.1 fallback when client doesn't support h2
2. ALPN negotiation edge cases
3. Certificate reload without dropping connections
4. Auth failures (various JWT errors)
5. Rate limiting across protocols
6. Large file transfers (1GB+)
7. Many concurrent connections (1000+)

---

### ⏳ Phase 8: Load Testing (PENDING)
**Duration**: Day 23 (1 day) | **Status**: ⏳ Pending

**Tools**: `wrk`, `h2load`

**Metrics**:
- Requests/sec (target: >1,000 for HTTP/2)
- p50/p99 latency
- Memory usage under load
- CPU usage
- Connection handling capacity

**Acceptance**: HTTP/2 within 120% of HTTP/1.1 baseline performance

---

### ⏳ Phase 9: Prometheus Metrics (PENDING)
**Duration**: Day 24 (1 day) | **Status**: ⏳ Pending

**Metrics to Expose**:
```rust
// Request metrics
proxy_requests_total{protocol="h2|http/1.1", status="200|407|403|429|502"}
proxy_request_duration_seconds{protocol="h2|http/1.1"}
proxy_bytes_transferred{direction="sent|received", protocol="h2|http/1.1"}

// Connection metrics
proxy_active_connections{protocol="h2|http/1.1"}
proxy_active_streams{protocol="h2"} // HTTP/2 only

// Auth metrics
proxy_auth_failures_total{reason="missing|invalid|expired|region"}

// Rate limit metrics
proxy_rate_limit_exceeded_total
proxy_active_tokens

// System metrics
proxy_memory_usage_bytes
proxy_cpu_usage_percent
```

---

### ⏳ Phase 10: Production Deployment (PENDING)
**Duration**: Day 25 (1 day) | **Status**: ⏳ Pending

**Deployment Strategy**: Gradual rollout

| Week | Traffic % | Monitoring Focus |
|------|-----------|------------------|
| 1 | 0% (staging only) | Stability, memory leaks |
| 2 | 10% | Latency, error rate |
| 3 | 50% | Performance vs Go proxy |
| 4 | 100% | Full migration complete |

**Rollback Plan**: <10 minutes to revert to Go proxy via load balancer

**Docker Deployment**:
```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/probe-proxy /usr/local/bin/
CMD ["probe-proxy"]
```

---

## Current Architecture

```
Client (Electron/Chromium)
    ↓ TLS + ALPN
    ↓
Rust Proxy (0.0.0.0:443)
    ├─ ALPN: h2 → serve_h2()
    │   └─ h2::server::handshake()
    │       └─ HTTP/2 Extended CONNECT
    │           ├─ JWT Auth (config.jwt_validator)
    │           ├─ Rate Limit (config.rate_limiter)
    │           ├─ Parse Authority
    │           ├─ Connect Upstream (tokio::net::TcpStream)
    │           └─ Bidirectional Stream Tunnel
    │
    └─ ALPN: http/1.1 → serve_http1()
        └─ Hyper HTTP/1.1 Server
            └─ HTTP/1.1 CONNECT
                ├─ JWT Auth ✅
                ├─ Rate Limit ✅
                ├─ Parse Authority ✅
                ├─ Connect Upstream ✅
                └─ Bidirectional TCP Tunnel ✅

Backend API (FastAPI)
    ↓ HTTPS
    ↓ POST /api/proxy-logs
    └─ Database (PostgreSQL)
```

---

## Key Files Structure

```
src/
├── main.rs              # ✅ Server entry + ALPN routing (Phase 1)
├── config.rs            # ✅ Environment configuration (Phase 1, 2)
├── tls.rs               # ✅ TLS + ALPN setup (Phase 1)
├── reload.rs            # ✅ Certificate hot-reload (Phase 1)
├── auth.rs              # ✅ JWT validation (Phase 2)
├── rate_limiter.rs      # ✅ Token bucket rate limiter (Phase 2)
├── server.rs            # ✅ HTTP/1.1 handler (Phase 3)
│                        # ⏳ HTTP/2 handler (Phase 4 - IN PROGRESS)
├── logger.rs            # ⏳ Request/response logging (Phase 6)
└── metrics.rs           # ⏳ Prometheus metrics (Phase 9)

Cargo.toml               # ✅ Dependencies configured
.env                     # ✅ Configuration
Dockerfile               # ⏳ Container image (Phase 10)
```

---

## Dependencies Status

```toml
[dependencies]
tokio = { version = "1.35", features = ["full", "signal"] }  # ✅ Installed
hyper = { version = "1.1", features = ["server", "http1", "http2"] }  # ✅ Installed
h2 = "0.4"                                                    # ✅ Installed
tokio-rustls = "0.25"                                         # ✅ Installed
rustls = "0.22"                                               # ✅ Installed
jsonwebtoken = "9.2"                                          # ✅ Installed
lru = "0.12"                                                  # ✅ Installed
prometheus = "0.13"                                           # ✅ Installed
tracing = "0.1"                                               # ✅ Installed
```

---

## Performance Targets

| Metric | HTTP/1.1 Baseline | HTTP/2 Target | Status |
|--------|-------------------|---------------|--------|
| Requests/sec | 1,200 | >1,000 | ⏳ TBD |
| p50 latency | 45ms | <60ms | ⏳ TBD |
| p99 latency | 120ms | <180ms | ⏳ TBD |
| Concurrent streams | N/A | 100+ | ⏳ TBD |
| Memory (100 streams) | 80MB | <120MB | ⏳ TBD |

**Acceptance Criteria**: HTTP/2 performance within 120% of HTTP/1.1 baseline

---

## Testing Progress

### Phase 1 Tests: ✅ 10 tests passing
- TLS certificate loading
- ALPN configuration
- Reloadable acceptor creation

### Phase 2 Tests: ✅ 32 tests passing
- JWT validation (10 tests)
- Rate limiter (12 tests)
- Config validation (8 tests)
- Reload module (2 tests)

### Phase 3 Tests: ✅ 43 tests passing
- Authority parsing (2 tests, 13 cases)
- Error handlers (2 tests)
- End-to-end CONNECT flow (7 integration tests)

### Phase 4 Tests: ⏳ Pending
- HTTP/2 CONNECT handler
- Stream multiplexing
- Flow control
- Error handling

**Total Current Test Coverage**: 43 tests, all passing

---

## Timeline Summary

| Phase | Days | Status | Test Count |
|-------|------|--------|------------|
| Phase 1: TLS + ALPN | 1-2 | ✅ Complete | 10 |
| Phase 2: Auth + Rate Limit | 3-6 | ✅ Complete | 32 |
| Phase 3: HTTP/1.1 CONNECT | 7-10 | ✅ Complete | 43 |
| Phase 4: HTTP/2 CONNECT | 11-17 | ⏳ Ready | 0 |
| Phase 5: Flow Control | 18-19 | ⏳ Pending | 0 |
| Phase 6: Logging | 20 | ⏳ Pending | 0 |
| Phase 7: Integration Tests | 21-22 | ⏳ Pending | 0 |
| Phase 8: Load Testing | 23 | ⏳ Pending | 0 |
| Phase 9: Metrics | 24 | ⏳ Pending | 0 |
| Phase 10: Deployment | 25 | ⏳ Pending | 0 |

**Current Status**: Day 10 complete, Day 11 starting
**Next Milestone**: Phase 4 Go/No-Go Checkpoint (Day 17)

---

## Risk Assessment

| Risk | Impact | Mitigation | Status |
|------|--------|------------|--------|
| HTTP/2 stream handling complexity | High | Direct h2 crate usage, comprehensive testing | ✅ Planned |
| Performance regression vs Go | High | Load testing, 120% acceptance threshold | ⏳ Pending |
| TLS certificate issues | Medium | Hot-reload feature, comprehensive testing | ✅ Implemented |
| Memory leaks with many streams | Medium | Regular profiling, cleanup tasks | ⏳ Pending |
| Production deployment issues | Medium | Gradual rollout, <10min rollback | ⏳ Pending |

---

## Next Steps (Phase 4)

**Immediate Tasks** (Day 11):
1. ✅ Update master plan document with current progress
2. ⏳ Implement h2::server handshake in serve_h2()
3. ⏳ Add basic HTTP/2 connection acceptance
4. ⏳ Add logging for HTTP/2 connections
5. ⏳ Test with openssl s_client

**Tomorrow** (Day 12-13):
- Implement HTTP/2 CONNECT request validation
- Integrate JWT authentication for HTTP/2
- Integrate rate limiting for HTTP/2
- Add authority parsing

**End of Week** (Day 14-17):
- Implement bidirectional stream tunneling
- Add comprehensive error handling
- Write integration tests
- Test with nghttp client
- Phase 4 Go/No-Go decision

---

## Success Metrics

**Phase 3 Success** ✅:
- ✅ All 43 tests passing
- ✅ HTTP/1.1 CONNECT fully functional
- ✅ JWT auth integrated
- ✅ Rate limiting integrated
- ✅ Comprehensive error handling
- ✅ Authority validation implemented
- ✅ Integration tests covering all paths

**Phase 4 Success Criteria** (TBD):
- All HTTP/2 CONNECT tests passing
- nghttp client successfully connects
- Stream multiplexing works (10+ concurrent)
- Memory stable under load
- Performance within 120% of baseline
- All auth/rate-limit paths tested

---

## Contact & Support

**Repository**: pinaka-rust-proxy
**Current Branch**: staging
**Documentation**: This file + README.md
**Engineering Team**: ProbeOps Platform Team

---

**Document End**
Last Updated: 2025-11-20
Next Review: After Phase 4 completion (Day 17)
