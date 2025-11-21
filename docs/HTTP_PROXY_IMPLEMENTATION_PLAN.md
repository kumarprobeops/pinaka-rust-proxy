# HTTP Proxy Implementation Plan
## Full HTTP Forwarding with Security Safeguards

**Document Version**: 1.0
**Date**: 2025-11-21
**Status**: Planning Phase
**Estimated Effort**: 16-24 hours development + 8 hours testing

---

## Executive Summary

Implement full HTTP proxy support (GET, POST, HEAD, etc.) to resolve Chrome/Playwright multi-tab failures while maintaining enterprise-grade security through JWT authentication, destination filtering, IP-per-token limits, and comprehensive abuse detection.

**Current Issue**: Proxy returns `405 Method Not Allowed` for non-CONNECT requests, breaking browser connectivity probes and causing tab failures after initial success.

**Solution**: Implement complete HTTP forwarding with layered security controls.

---

## 1. Requirements Analysis

### 1.1 Functional Requirements

| Requirement | Priority | Description |
|-------------|----------|-------------|
| **F1: HTTP Method Support** | P0 (Critical) | Support GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS |
| **F2: Request Forwarding** | P0 (Critical) | Forward requests to upstream with proper headers |
| **F3: Response Streaming** | P0 (Critical) | Stream responses back to client |
| **F4: Body Handling** | P0 (Critical) | Support request/response bodies for POST/PUT |
| **F5: HTTP/1.1 Support** | P0 (Critical) | Work with HTTP/1.1 connections |
| **F6: HTTP/2 Support** | P1 (High) | Work with HTTP/2 streams |

### 1.2 Security Requirements

| Requirement | Priority | Description | Risk Mitigated |
|-------------|----------|-------------|----------------|
| **S1: JWT Authentication** | P0 (Critical) | All requests must have valid JWT | Open proxy abuse |
| **S2: Destination Filtering** | P0 (Critical) | Block RFC1918, localhost, metadata IPs | Internal scanning, SSRF |
| **S3: IP-per-Token Limit** | P0 (Critical) | Max N unique IPs per token (configurable) | Token sharing, compromise |
| **S4: Hop-by-Hop Filtering** | P0 (Critical) | Strip Connection, TE, Upgrade, etc. | Header injection |
| **S5: Method Whitelist** | P0 (Critical) | Block TRACE, CONNECT-over-HTTP | XST attacks, protocol abuse |
| **S6: Body Size Limits** | P1 (High) | Max 10MB request/response bodies | DoS, memory exhaustion |
| **S7: Request Timeout** | P1 (High) | Max 30s per request | Resource exhaustion |
| **S8: Comprehensive Logging** | P1 (High) | Log all HTTP requests with destinations | Abuse detection, forensics |
| **S9: Rate Limiting** | P0 (Critical) | Reuse existing token-based rate limiter | Request flooding |

### 1.3 Performance Requirements

| Metric | Target | Rationale |
|--------|--------|-----------|
| **Request Latency** | < 100ms overhead | User experience |
| **Throughput** | 1000 req/s per instance | Scalability |
| **Memory per Request** | < 1MB | Resource efficiency |
| **Concurrent Connections** | 100 per token | Multi-tab support |

---

## 2. Architecture Design

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         HTTP Proxy Flow                          │
└─────────────────────────────────────────────────────────────────┘

Client Request (GET http://example.com/page)
    │
    ├──> [1] JWT Authentication (S1)
    │        ├─ Extract token from Proxy-Authorization header
    │        ├─ Validate signature, expiry, region
    │        └─ Extract user_id, token_id, allowed_regions
    │
    ├──> [2] IP-per-Token Check (S3)
    │        ├─ Extract client IP from connection
    │        ├─ Check: IP count for this token_id < limit
    │        ├─ Track: Add IP to token's IP set (LRU cache)
    │        └─ Reject if limit exceeded
    │
    ├──> [3] Rate Limiting (S9)
    │        ├─ Check: token_id within rate limit
    │        └─ Reject if exceeded
    │
    ├──> [4] Request Validation (S5, S4)
    │        ├─ Validate: Method in whitelist
    │        ├─ Validate: Absolute-form URI
    │        ├─ Parse: scheme, authority, path
    │        └─ Filter: Strip hop-by-hop headers
    │
    ├──> [5] Destination Filtering (S2)
    │        ├─ Parse destination host/IP
    │        ├─ Check: Not RFC1918 (10.0.0.0/8, etc.)
    │        ├─ Check: Not localhost (127.0.0.0/8)
    │        ├─ Check: Not metadata (169.254.0.0/16)
    │        └─ Reject if blocked
    │
    ├──> [6] Body Size Check (S6)
    │        ├─ Read request body (if present)
    │        ├─ Check: Size < MAX_BODY_SIZE
    │        └─ Reject if too large
    │
    ├──> [7] Upstream Connection (S7)
    │        ├─ Build reqwest HTTP client
    │        ├─ Set timeout (30s)
    │        ├─ Add filtered headers
    │        ├─ Attach body (if present)
    │        └─ Send request
    │
    ├──> [8] Response Handling (S6, S4)
    │        ├─ Receive response headers
    │        ├─ Check: Body size < MAX_BODY_SIZE
    │        ├─ Filter: Strip hop-by-hop headers
    │        └─ Stream body to client
    │
    └──> [9] Logging & Metrics (S8)
             ├─ Log: method, url, status, bytes, duration
             ├─ Log: user_id, token_id, client_ip
             └─ Send to backend analytics
```

### 2.2 New Components

#### 2.2.1 IP Tracker (ip_tracker.rs)

**Purpose**: Enforce unique IP limit per JWT token

**Data Structure**:
```rust
struct IpTracker {
    // LRU cache: token_id -> Set<IpAddr>
    token_ips: Arc<Mutex<LruCache<String, HashSet<IpAddr>>>>,
    max_ips_per_token: usize,
    cache_ttl_seconds: u64,
}
```

**Key Methods**:
- `check_and_track(token_id: &str, client_ip: IpAddr) -> Result<(), IpTrackerError>`
- `get_ip_count(token_id: &str) -> usize`
- `cleanup()` - Remove stale entries

**Configuration** (environment variables):
- `MAX_IPS_PER_TOKEN` - Default: 5
- `IP_TRACKER_CACHE_SIZE` - Default: 10,000 tokens
- `IP_TRACKER_TTL_SECONDS` - Default: 3600 (1 hour)

#### 2.2.2 Destination Filter (destination_filter.rs)

**Purpose**: Block internal/metadata destinations

**Blocked Ranges**:
```rust
const BLOCKED_IP_RANGES: &[IpNetwork] = &[
    // RFC1918 - Private networks
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",

    // Localhost
    "127.0.0.0/8",
    "::1/128",

    // Link-local
    "169.254.0.0/16",
    "fe80::/10",

    // Metadata services
    "169.254.169.254/32",  // AWS, Azure, GCP
    "fd00:ec2::254/128",    // AWS IPv6
];
```

**Key Methods**:
- `is_allowed(host: &str) -> Result<bool, DestinationError>`
- `resolve_and_check(host: &str) -> Result<(), DestinationError>`

**Configuration**:
- `DESTINATION_FILTER_MODE` - "block" (default) or "allow"
- `DESTINATION_ALLOWLIST` - Comma-separated domains (optional)
- `DESTINATION_BLOCKLIST_EXTRA` - Additional IPs/CIDRs to block

#### 2.2.3 HTTP Forwarder (http_forwarder.rs)

**Purpose**: Core HTTP request forwarding logic

**Key Methods**:
- `forward_http1_request()` - HTTP/1.1 handler
- `forward_http2_request()` - HTTP/2 stream handler
- `build_upstream_request()` - Construct reqwest request
- `filter_hop_by_hop_headers()` - Remove unsafe headers
- `stream_response()` - Stream response to client

---

## 3. Implementation Phases

### Phase 1: Foundation (4 hours)
**Goal**: Set up new modules and data structures

**Tasks**:
1. Create `src/ip_tracker.rs`
   - Implement `IpTracker` struct with LRU cache
   - Add configuration parsing
   - Add unit tests for IP tracking logic

2. Create `src/destination_filter.rs`
   - Implement IP range checking
   - Add DNS resolution with caching
   - Add unit tests for filtering logic

3. Update `src/config.rs`
   - Add IP tracker config fields
   - Add destination filter config
   - Add HTTP proxy config (body limits, timeouts)

4. Update `Cargo.toml` dependencies
   - Add `ipnetwork = "0.20"` for CIDR parsing
   - Add `dns-lookup = "2.0"` for host resolution

**Deliverables**:
- ✅ `ip_tracker.rs` with 10+ unit tests
- ✅ `destination_filter.rs` with 15+ unit tests
- ✅ Updated config with validation
- ✅ All tests passing

### Phase 2: HTTP/1.1 Forwarding (6 hours)
**Goal**: Implement full HTTP/1.1 proxy support

**Tasks**:
1. Create `src/http_forwarder.rs`
   - Implement `forward_http1_request()`
   - Request validation (method, URI, headers)
   - Destination filtering integration
   - IP tracking integration
   - Body size limiting
   - Upstream request building
   - Response streaming with size limits

2. Update `src/server.rs`
   - Replace stub 204 response with `forward_http1_request()` call
   - Add proper error handling
   - Add request/response logging

3. Integration testing
   - Test with curl
   - Test with Chrome probes
   - Test error cases

**Deliverables**:
- ✅ `http_forwarder.rs` with HTTP/1.1 support
- ✅ 20+ integration tests
- ✅ HTTP/1.1 working end-to-end

### Phase 3: HTTP/2 Forwarding (4 hours)
**Goal**: Extend support to HTTP/2 streams

**Tasks**:
1. Implement `forward_http2_request()` in `http_forwarder.rs`
   - Adapt HTTP/1.1 logic for h2 streams
   - Handle stream-specific errors
   - Support HTTP/2 push (optional)

2. Update HTTP/2 handler in `src/server.rs`
   - Replace stub with `forward_http2_request()` call
   - Add stream cleanup

3. Integration testing
   - Test with HTTP/2 clients
   - Test with Chrome over HTTP/2
   - Test concurrent streams

**Deliverables**:
- ✅ HTTP/2 forwarding working
- ✅ 15+ HTTP/2-specific tests
- ✅ Both protocols working together

### Phase 4: Security Hardening (3 hours)
**Goal**: Add comprehensive security checks

**Tasks**:
1. Implement hop-by-hop header filtering
   - Create header filter function
   - Test with malicious headers
   - Verify no leaks

2. Add request/response timeouts
   - Implement timeout middleware
   - Test with slow servers
   - Test with large responses

3. Add comprehensive logging
   - Log all HTTP requests
   - Include security-relevant fields
   - Test log output format

4. Security testing
   - Test RFC1918 blocking
   - Test metadata IP blocking
   - Test IP limit enforcement
   - Test method whitelist
   - Test body size limits

**Deliverables**:
- ✅ Security test suite (30+ tests)
- ✅ All security controls verified
- ✅ Penetration testing complete

### Phase 5: Performance & Production (3 hours)
**Goal**: Optimize and prepare for production

**Tasks**:
1. Performance optimization
   - Profile with criterion
   - Optimize hot paths
   - Memory leak testing

2. Load testing
   - Test with h2load
   - Test with concurrent clients
   - Verify resource limits

3. Documentation
   - API documentation
   - Security documentation
   - Operations guide

**Deliverables**:
- ✅ Performance benchmarks
- ✅ Load test results
- ✅ Production-ready documentation

---

## 4. Testing Strategy

### 4.1 Unit Tests (50+ tests)

#### IP Tracker Tests (10 tests)
```rust
#[cfg(test)]
mod ip_tracker_tests {
    #[test]
    fn test_track_new_ip() { /* ... */ }

    #[test]
    fn test_ip_limit_enforcement() { /* ... */ }

    #[test]
    fn test_duplicate_ip_allowed() { /* ... */ }

    #[test]
    fn test_lru_eviction() { /* ... */ }

    #[test]
    fn test_ttl_expiration() { /* ... */ }

    #[test]
    fn test_concurrent_tracking() { /* ... */ }

    #[test]
    fn test_ipv4_and_ipv6() { /* ... */ }

    #[test]
    fn test_multiple_tokens() { /* ... */ }

    #[test]
    fn test_cleanup() { /* ... */ }

    #[test]
    fn test_get_ip_count() { /* ... */ }
}
```

#### Destination Filter Tests (15 tests)
```rust
#[cfg(test)]
mod destination_filter_tests {
    #[test]
    fn test_block_rfc1918_10() { /* ... */ }

    #[test]
    fn test_block_rfc1918_172() { /* ... */ }

    #[test]
    fn test_block_rfc1918_192() { /* ... */ }

    #[test]
    fn test_block_localhost() { /* ... */ }

    #[test]
    fn test_block_link_local() { /* ... */ }

    #[test]
    fn test_block_metadata_aws() { /* ... */ }

    #[test]
    fn test_allow_public_ip() { /* ... */ }

    #[test]
    fn test_allow_public_domain() { /* ... */ }

    #[test]
    fn test_dns_resolution() { /* ... */ }

    #[test]
    fn test_ipv6_filtering() { /* ... */ }

    #[test]
    fn test_invalid_host() { /* ... */ }

    #[test]
    fn test_allowlist_mode() { /* ... */ }

    #[test]
    fn test_custom_blocklist() { /* ... */ }

    #[test]
    fn test_dns_timeout() { /* ... */ }

    #[test]
    fn test_cached_resolution() { /* ... */ }
}
```

#### HTTP Forwarder Tests (25 tests)
```rust
#[cfg(test)]
mod http_forwarder_tests {
    #[test]
    fn test_get_request() { /* ... */ }

    #[test]
    fn test_post_with_body() { /* ... */ }

    #[test]
    fn test_head_request() { /* ... */ }

    #[test]
    fn test_put_request() { /* ... */ }

    #[test]
    fn test_delete_request() { /* ... */ }

    #[test]
    fn test_options_request() { /* ... */ }

    #[test]
    fn test_patch_request() { /* ... */ }

    #[test]
    fn test_block_trace_method() { /* ... */ }

    #[test]
    fn test_absolute_uri_validation() { /* ... */ }

    #[test]
    fn test_hop_by_hop_filtering() { /* ... */ }

    #[test]
    fn test_request_body_size_limit() { /* ... */ }

    #[test]
    fn test_response_body_size_limit() { /* ... */ }

    #[test]
    fn test_request_timeout() { /* ... */ }

    #[test]
    fn test_invalid_uri() { /* ... */ }

    #[test]
    fn test_missing_authority() { /* ... */ }

    #[test]
    fn test_authentication_required() { /* ... */ }

    #[test]
    fn test_rate_limit_enforcement() { /* ... */ }

    #[test]
    fn test_ip_limit_enforcement() { /* ... */ }

    #[test]
    fn test_destination_blocked() { /* ... */ }

    #[test]
    fn test_upstream_error_handling() { /* ... */ }

    #[test]
    fn test_chunked_encoding() { /* ... */ }

    #[test]
    fn test_content_length_validation() { /* ... */ }

    #[test]
    fn test_header_forwarding() { /* ... */ }

    #[test]
    fn test_status_code_forwarding() { /* ... */ }

    #[test]
    fn test_logging() { /* ... */ }
}
```

### 4.2 Integration Tests (20 tests)

```rust
// tests/http_proxy_integration.rs

#[tokio::test]
async fn test_http_get_google() { /* ... */ }

#[tokio::test]
async fn test_http_post_with_json() { /* ... */ }

#[tokio::test]
async fn test_chrome_connectivity_probe() { /* ... */ }

#[tokio::test]
async fn test_multiple_concurrent_requests() { /* ... */ }

#[tokio::test]
async fn test_http1_and_http2_mix() { /* ... */ }

#[tokio::test]
async fn test_ip_limit_across_requests() { /* ... */ }

#[tokio::test]
async fn test_rate_limit_triggers() { /* ... */ }

#[tokio::test]
async fn test_blocked_destination_rejection() { /* ... */ }

#[tokio::test]
async fn test_large_response_streaming() { /* ... */ }

#[tokio::test]
async fn test_slow_server_timeout() { /* ... */ }

#[tokio::test]
async fn test_invalid_jwt_rejection() { /* ... */ }

#[tokio::test]
async fn test_expired_jwt_rejection() { /* ... */ }

#[tokio::test]
async fn test_wrong_region_rejection() { /* ... */ }

#[tokio::test]
async fn test_playwright_multi_tab() { /* ... */ }

#[tokio::test]
async fn test_chrome_extension_requests() { /* ... */ }

#[tokio::test]
async fn test_http_to_https_redirect() { /* ... */ }

#[tokio::test]
async fn test_authentication_challenge() { /* ... */ }

#[tokio::test]
async fn test_connection_reuse() { /* ... */ }

#[tokio::test]
async fn test_error_recovery() { /* ... */ }

#[tokio::test]
async fn test_metrics_collection() { /* ... */ }
```

### 4.3 Security Tests (30 tests)

```rust
// tests/security_tests.rs

#[tokio::test]
async fn test_block_ssrf_localhost() { /* ... */ }

#[tokio::test]
async fn test_block_ssrf_rfc1918_10() { /* ... */ }

#[tokio::test]
async fn test_block_ssrf_metadata_service() { /* ... */ }

#[tokio::test]
async fn test_block_header_injection() { /* ... */ }

#[tokio::test]
async fn test_block_trace_method() { /* ... */ }

#[tokio::test]
async fn test_ip_limit_single_token() { /* ... */ }

#[tokio::test]
async fn test_ip_limit_different_tokens() { /* ... */ }

#[tokio::test]
async fn test_request_body_bomb() { /* ... */ }

#[tokio::test]
async fn test_response_body_bomb() { /* ... */ }

#[tokio::test]
async fn test_slowloris_attack() { /* ... */ }

// ... 20 more security tests
```

### 4.4 Performance Tests

```rust
// benches/http_proxy_benchmarks.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_http_get(c: &mut Criterion) {
    c.bench_function("http_get", |b| {
        b.iter(|| {
            // HTTP GET request
            black_box(/* ... */);
        });
    });
}

fn bench_http_post(c: &mut Criterion) { /* ... */ }

fn bench_ip_tracking(c: &mut Criterion) { /* ... */ }

fn bench_destination_filter(c: &mut Criterion) { /* ... */ }

criterion_group!(benches, bench_http_get, bench_http_post, bench_ip_tracking, bench_destination_filter);
criterion_main!(benches);
```

---

## 5. Configuration

### 5.1 Environment Variables

```bash
# HTTP Proxy Configuration
HTTP_PROXY_ENABLED=true                    # Enable HTTP forwarding (default: true)
MAX_REQUEST_BODY_SIZE=10485760             # 10MB max request body (default: 10MB)
MAX_RESPONSE_BODY_SIZE=10485760            # 10MB max response body (default: 10MB)
HTTP_REQUEST_TIMEOUT_SECONDS=30            # Request timeout (default: 30s)

# IP Tracking Configuration
MAX_IPS_PER_TOKEN=5                        # Max unique IPs per token (default: 5)
IP_TRACKER_CACHE_SIZE=10000                # LRU cache size (default: 10,000 tokens)
IP_TRACKER_TTL_SECONDS=3600                # IP tracking TTL (default: 1 hour)

# Destination Filtering
DESTINATION_FILTER_MODE=block              # "block" or "allow" (default: block)
DESTINATION_ALLOWLIST=                     # Comma-separated domains (optional)
DESTINATION_BLOCKLIST_EXTRA=               # Additional IPs/CIDRs to block (optional)

# Security
ALLOWED_HTTP_METHODS=GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS  # Whitelisted methods
STRIP_HOP_BY_HOP_HEADERS=true              # Strip dangerous headers (default: true)

# Logging
LOG_HTTP_REQUESTS=true                     # Log all HTTP requests (default: true)
LOG_HTTP_BODIES=false                      # Log request/response bodies (default: false)
```

### 5.2 Updated Config Struct

```rust
// src/config.rs

pub struct Config {
    // ... existing fields ...

    // HTTP Proxy Config
    pub http_proxy_enabled: bool,
    pub max_request_body_size: usize,
    pub max_response_body_size: usize,
    pub http_request_timeout: Duration,
    pub allowed_http_methods: HashSet<Method>,
    pub strip_hop_by_hop: bool,

    // IP Tracking
    pub max_ips_per_token: usize,
    pub ip_tracker: Arc<IpTracker>,

    // Destination Filtering
    pub destination_filter: Arc<DestinationFilter>,

    // Logging
    pub log_http_requests: bool,
    pub log_http_bodies: bool,
}
```

---

## 6. File Changes Summary

### New Files (3)
- `src/ip_tracker.rs` (~300 lines)
- `src/destination_filter.rs` (~400 lines)
- `src/http_forwarder.rs` (~600 lines)
- `docs/HTTP_PROXY_SECURITY.md` (~100 lines)

### Modified Files (5)
- `src/server.rs` - Replace stubs with forwarding calls (~50 line changes)
- `src/config.rs` - Add new config fields (~100 line changes)
- `src/lib.rs` - Export new modules (~5 line changes)
- `Cargo.toml` - Add dependencies (~10 line changes)
- `README.md` - Update documentation (~50 line changes)

### Test Files (3)
- `tests/http_proxy_integration.rs` (~500 lines, new)
- `tests/security_tests.rs` (~800 lines, new)
- `benches/http_proxy_benchmarks.rs` (~200 lines, new)

**Total New Code**: ~3,000 lines
**Total Modified Code**: ~200 lines
**Total Tests**: ~1,500 lines

---

## 7. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| **Performance degradation** | Medium | High | Benchmark before/after, optimize hot paths |
| **Memory leaks** | Low | High | Valgrind testing, bounds checking |
| **Security bypass** | Low | Critical | Comprehensive security test suite, penetration testing |
| **Breaking changes** | Low | Medium | Maintain backward compatibility, feature flag |
| **Token abuse** | Medium | Medium | IP limits, rate limits, monitoring |
| **Internal network access** | Low | Critical | Strict destination filtering, allowlist mode |
| **DoS via large bodies** | Medium | High | Size limits, timeouts, memory monitoring |

---

## 8. Success Criteria

### Functional
- ✅ Chrome/Playwright can open 10+ tabs without errors
- ✅ All HTTP methods work (GET, POST, etc.)
- ✅ Both HTTP/1.1 and HTTP/2 supported
- ✅ Request/response bodies forward correctly
- ✅ Large responses (>1MB) stream properly

### Security
- ✅ No requests reach RFC1918 addresses
- ✅ No requests reach metadata endpoints
- ✅ IP-per-token limit enforced
- ✅ Rate limiting still works
- ✅ JWT authentication required
- ✅ No hop-by-hop header leaks
- ✅ Body size limits enforced
- ✅ Timeouts prevent hangs

### Performance
- ✅ < 100ms overhead per request
- ✅ 1000 req/s throughput
- ✅ < 1MB memory per request
- ✅ No memory leaks under load

### Testing
- ✅ 100+ tests passing
- ✅ 90%+ code coverage
- ✅ All security tests passing
- ✅ Load tests successful

---

## 9. Implementation Timeline

| Phase | Duration | Tasks | Deliverables |
|-------|----------|-------|--------------|
| **Phase 1: Foundation** | 4 hours | IP tracker, destination filter, config | New modules + tests |
| **Phase 2: HTTP/1.1** | 6 hours | HTTP/1.1 forwarding logic | Working HTTP/1.1 proxy |
| **Phase 3: HTTP/2** | 4 hours | HTTP/2 stream forwarding | Working HTTP/2 proxy |
| **Phase 4: Security** | 3 hours | Hardening, testing | Security verified |
| **Phase 5: Production** | 3 hours | Performance, docs | Production-ready |
| **Total** | **20 hours** | | Full implementation |

---

## 10. Deployment Strategy

### 10.1 Development
1. Implement on feature branch `feature/http-proxy-support`
2. Run all tests locally
3. Manual testing with curl + Chrome
4. Code review by team

### 10.2 Staging
1. Deploy to staging environment
2. Run integration tests
3. Manual testing with Playwright
4. Security scanning
5. Performance benchmarking

### 10.3 Production
1. Feature flag enabled for canary users (1%)
2. Monitor metrics for 24 hours
3. Gradually increase to 10%, 50%, 100%
4. Full rollout after 1 week

### 10.4 Rollback Plan
1. Feature flag can disable HTTP proxy instantly
2. Falls back to 204 stub responses
3. No data loss
4. Zero downtime rollback

---

## 11. Monitoring & Alerts

### Metrics to Track
- `http_proxy_requests_total` - Total HTTP requests
- `http_proxy_blocked_destinations` - Blocked SSRF attempts
- `http_proxy_ip_limit_violations` - IP limit violations
- `http_proxy_body_size_errors` - Body too large errors
- `http_proxy_timeout_errors` - Timeout errors
- `http_proxy_latency_seconds` - Request latency histogram
- `http_proxy_bytes_transferred` - Total bytes proxied

### Alerts
- **Critical**: HTTP proxy error rate > 5%
- **Warning**: IP limit violations > 100/min
- **Warning**: Destination blocks > 50/min
- **Info**: HTTP proxy usage increase > 50%

---

## 12. Next Steps

1. **Get Approval**: Review this plan with team
2. **Set Up Branch**: Create `feature/http-proxy-support`
3. **Phase 1 Start**: Begin IP tracker implementation
4. **Daily Standups**: Track progress, blockers
5. **Code Reviews**: After each phase
6. **Final Review**: Before staging deployment

---

## Appendix A: Code Examples

### Example: IP Tracker Usage

```rust
// Check IP limit before forwarding
let client_ip = extract_client_ip(&req)?;

if let Err(e) = config.ip_tracker.check_and_track(&claims.token_id, client_ip).await {
    warn!("[HTTP] IP limit exceeded for token {}: {}", claims.token_id, e);
    return Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from("IP limit exceeded for this token")))
        .unwrap());
}
```

### Example: Destination Filtering

```rust
// Check destination before connecting
let host = extract_host(&target_url)?;

if !config.destination_filter.is_allowed(&host).await? {
    warn!("[HTTP] Blocked destination: {}", host);

    config.request_logger.log_request(
        claims.token_id.clone(),
        claims.user_id as i32,
        method.as_str().to_string(),
        target_url.clone(),
        Some(403),
        0,
        Some(start_time.elapsed().as_millis() as i64),
        false,
        false,
        Some(format!("Blocked destination: {}", host)),
    ).await;

    return Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from("Destination not allowed")))
        .unwrap());
}
```

---

**End of Plan Document**

**Ready to Start**: Approval needed to begin Phase 1
**Questions**: Contact dev team for clarifications
**Updates**: This document will be updated as implementation progresses
