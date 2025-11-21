# Engineering Feedback V2 - Concise Response

**Date**: 2025-11-21
**Status**: Critical Issues Addressed

---

## Critical Fixes Required

### 1. HTTP/1.1 Forwarding - Complete Rewrite Needed

**Problems:**
- ❌ Connects to hostname (allows DNS rebinding bypass)
- ❌ No TLS support for https:// targets
- ❌ Sends absolute-form URI instead of origin-form
- ❌ No SNI/cert verification

**Solution:**

```rust
// src/http_forwarder.rs - Correct implementation

pub async fn forward_http1_request(
    req: Request<Incoming>,
    config: Arc<Config>,
    claims: Claims,
    client_ip: IpAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {

    // 1. Parse absolute-form URI
    let uri = req.uri();
    let scheme = uri.scheme_str().ok_or(ProxyError::InvalidUri)?;
    let authority = uri.authority().ok_or(ProxyError::InvalidUri)?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });

    // 2. Destination filter - returns vetted IPs (no re-resolution)
    let vetted_ips = config.destination_filter.check_and_resolve(host).await?;

    // 3. IP limit check
    config.ip_tracker.check_and_track(&claims.token_id, client_ip).await?;

    // 4. Rate limit check
    config.rate_limiter.check(&claims.token_id).await?;

    // 5. Connect to VETTED IP (not hostname)
    let target_ip = vetted_ips[0]; // Use first vetted IP
    let addr = SocketAddr::new(target_ip, port);

    let stream = match scheme {
        "http" => {
            // Plain HTTP
            let tcp = timeout(
                Duration::from_secs(10),
                TcpStream::connect(addr)
            ).await??;
            Either::Left(TokioIo::new(tcp))
        }
        "https" => {
            // HTTPS with TLS + SNI
            let tcp = timeout(
                Duration::from_secs(10),
                TcpStream::connect(addr)
            ).await??;

            let tls_config = config.tls_client_config.clone();
            let connector = TlsConnector::from(tls_config);

            // CRITICAL: Use original hostname for SNI, not IP
            let server_name = ServerName::try_from(host)
                .map_err(|_| ProxyError::InvalidServerName)?;

            let tls_stream = connector.connect(server_name, tcp).await?;
            Either::Right(TokioIo::new(tls_stream))
        }
        _ => return Err(ProxyError::UnsupportedScheme(scheme.to_string())),
    };

    // 6. Create hyper HTTP/1 connection
    let (mut sender, conn) = http1::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("Connection error: {}", e);
        }
    });

    // 7. Build origin-form request (NOT absolute-form)
    let path_and_query = uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let origin_uri = Uri::builder()
        .path_and_query(path_and_query)
        .build()?;

    let mut upstream_req = Request::builder()
        .method(req.method())
        .uri(origin_uri)  // origin-form, not absolute-form
        .version(Version::HTTP_11);

    // 8. Copy filtered headers + ensure Host header
    let filtered_headers = filter_request_headers(req.headers());
    for (name, value) in filtered_headers {
        upstream_req = upstream_req.header(name, value);
    }

    // Ensure Host header (RFC 7230 § 5.4)
    if !filtered_headers.contains_key("host") {
        upstream_req = upstream_req.header("host", authority.as_str());
    }

    // 9. Forward request with body limits
    let body = LimitedBody::new(
        req.into_body(),
        config.max_request_body_size,
        LimitBehavior::FailFast,
    );

    let upstream_resp = timeout(
        Duration::from_secs(config.http_request_timeout),
        sender.send_request(upstream_req.body(body)?)
    ).await??;

    // 10. Build response with limited body
    let mut resp = Response::builder()
        .status(upstream_resp.status())
        .version(Version::HTTP_11);

    let filtered_resp_headers = filter_response_headers(upstream_resp.headers());
    for (name, value) in filtered_resp_headers {
        resp = resp.header(name, value);
    }

    let resp_body = LimitedBody::new(
        upstream_resp.into_body(),
        config.max_response_body_size,
        LimitBehavior::FailFast,
    );

    Ok(resp.body(BoxBody::new(resp_body))?)
}

enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>
    AsyncRead for Either<A, B> { /* ... */ }

impl<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>
    AsyncWrite for Either<A, B> { /* ... */ }
```

**Key Fixes:**
1. ✅ Connect to vetted IP, not hostname
2. ✅ TLS support with rustls + SNI (uses hostname for SNI, IP for connect)
3. ✅ Origin-form URI sent to upstream
4. ✅ Host header ensured
5. ✅ Separate connect timeout (10s)

---

### 2. Destination Filter - DNS Rotation Handling

**Problems:**
- ❌ Round-robin/geo DNS flagged as rebinding attack
- ❌ `::ffff:0:0/96` blocks all IPv4-mapped (false positive)
- ❌ Double lookup adds latency

**Solution:**

```rust
// src/destination_filter.rs

pub struct DestinationFilter {
    resolver: Arc<TokioAsyncResolver>,
    dns_cache: Arc<Mutex<LruCache<String, CachedResolution>>>,
    blocked_ranges: Vec<IpNetwork>,
}

struct CachedResolution {
    ips: Vec<IpAddr>,
    resolved_at: Instant,
    ttl: Duration,
}

impl DestinationFilter {
    /// Returns vetted IPs - caller MUST connect to these IPs, not re-resolve
    pub async fn check_and_resolve(&self, host: &str) -> Result<Vec<IpAddr>, DestinationError> {

        // 1. Resolve hostname
        let ips = self.resolve_with_cache(host).await?;

        // 2. Check ALL IPs against blocklist
        for ip in &ips {
            if self.is_ip_blocked(*ip) {
                return Err(DestinationError::BlockedIpRange(*ip));
            }
        }

        // 3. Return vetted IPs (no second lookup - caller uses these)
        Ok(ips)
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        for range in &self.blocked_ranges {
            if range.contains(ip) {
                return true;
            }
        }
        false
    }

    async fn resolve_with_cache(&self, host: &str) -> Result<Vec<IpAddr>, DestinationError> {
        let mut cache = self.dns_cache.lock().await;

        if let Some(cached) = cache.get(host) {
            if cached.resolved_at.elapsed() < cached.ttl {
                return Ok(cached.ips.clone());
            }
        }

        // Fresh DNS lookup
        let lookup = self.resolver.lookup_ip(host).await?;
        let ips: Vec<IpAddr> = lookup.iter().collect();

        cache.put(host.to_string(), CachedResolution {
            ips: ips.clone(),
            resolved_at: Instant::now(),
            ttl: Duration::from_secs(60),
        });

        Ok(ips)
    }
}

// Fixed blocklist - remove ::ffff:0:0/96
const BLOCKED_IP_RANGES: &[&str] = &[
    // IPv4 Private Networks
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",

    // IPv4 Localhost
    "127.0.0.0/8",

    // IPv4 Link-Local
    "169.254.0.0/16",

    // IPv4 Metadata
    "169.254.169.254/32",

    // IPv6 Localhost
    "::1/128",

    // IPv6 Link-Local
    "fe80::/10",

    // IPv6 ULA
    "fc00::/7",

    // IPv6 Metadata (AWS)
    "fd00:ec2::254/128",

    // NOTE: Removed ::ffff:0:0/96 to allow IPv4-mapped IPv6
];
```

**Key Fixes:**
1. ✅ Single DNS lookup, cache for 60s TTL
2. ✅ Return vetted IPs to caller (no re-resolution)
3. ✅ Removed `::ffff:0:0/96` blocklist
4. ✅ Accept DNS rotation (all IPs checked, any set allowed if all public)

---

### 3. Body Limiter - Complete Implementation

**Problems:**
- ❌ Truncated code
- ❌ Unclear error propagation
- ❌ Missing status codes

**Solution:**

```rust
// src/body_limiter.rs

use hyper::body::{Body, Bytes, Frame};
use pin_project::pin_project;

#[pin_project]
pub struct LimitedBody<B> {
    #[pin]
    inner: B,
    limit: usize,
    bytes_read: usize,
    behavior: LimitBehavior,
}

pub enum LimitBehavior {
    FailFast,      // Return error immediately when limit exceeded
}

impl<B: Body> LimitedBody<B> {
    pub fn new(inner: B, limit: usize, behavior: LimitBehavior) -> Self {
        Self { inner, limit, bytes_read: 0, behavior }
    }
}

impl<B: Body> Body for LimitedBody<B>
where
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = BodyLimitError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {

        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let new_total = *this.bytes_read + data.len();

                    if new_total > *this.limit {
                        // Limit exceeded
                        return Poll::Ready(Some(Err(BodyLimitError::LimitExceeded {
                            limit: *this.limit,
                            bytes_read: *this.bytes_read,
                        })));
                    }

                    *this.bytes_read = new_total;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(BodyLimitError::Upstream(e.into()))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BodyLimitError {
    #[error("Body size limit exceeded: {bytes_read}/{limit} bytes")]
    LimitExceeded { limit: usize, bytes_read: usize },

    #[error("Upstream body error: {0}")]
    Upstream(Box<dyn std::error::Error + Send + Sync>),
}

// In server.rs error handling:
match forward_http1_request(...).await {
    Ok(resp) => Ok(resp),
    Err(ProxyError::BodyLimitExceeded { limit, .. }) => {
        Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(format!(
                "Request or response body exceeded {limit} byte limit"
            ))))
            .unwrap())
    }
    Err(e) => Ok(error_response(e)),
}
```

**Key Fixes:**
1. ✅ Complete implementation with pin-project
2. ✅ Returns 413 Payload Too Large on limit exceeded
3. ✅ Error propagation to client with clear message
4. ✅ Simplified to FailFast only (no streaming modes)

---

### 4. IP Tracker - Fixed Implementation

**Problems:**
- ❌ `get_or_insert_mut` doesn't exist in LRU API
- ❌ TTL reset keeps entry hot in LRU
- ❌ `cleanup_expired` iter_mut while mutating rejected
- ❌ Dual-stack normalization applied after check

**Solution:**

```rust
// src/ip_tracker.rs

use lru::LruCache;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;

pub struct IpTracker {
    cache: Arc<Mutex<LruCache<String, TokenIpState>>>,
    max_ips_per_token: usize,
    entry_ttl: Duration,
}

struct TokenIpState {
    ips: BTreeSet<IpAddr>,
    created_at: Instant,
}

impl IpTracker {
    pub async fn check_and_track(
        &self,
        token_id: &str,
        client_ip: IpAddr,
    ) -> Result<(), IpTrackerError> {

        // 1. Normalize IP FIRST (before any checks)
        let normalized_ip = normalize_dual_stack_ip(client_ip);

        let mut cache = self.cache.lock().await;

        // 2. Get existing state or create new
        let state = match cache.get_mut(token_id) {
            Some(state) => {
                // Check TTL expiration
                if state.created_at.elapsed() > self.entry_ttl {
                    // Reset tracking
                    state.ips.clear();
                    state.created_at = Instant::now();
                }
                state
            }
            None => {
                // Create new entry
                cache.put(token_id.to_string(), TokenIpState {
                    ips: BTreeSet::new(),
                    created_at: Instant::now(),
                });
                cache.get_mut(token_id).unwrap()
            }
        };

        // 3. Check if IP already tracked
        if state.ips.contains(&normalized_ip) {
            return Ok(());  // Same IP, allowed
        }

        // 4. Check IP limit
        if state.ips.len() >= self.max_ips_per_token {
            return Err(IpTrackerError::LimitExceeded {
                token_id: token_id.to_string(),
                current_count: state.ips.len(),
                limit: self.max_ips_per_token,
                client_ip: normalized_ip,
            });
        }

        // 5. Add new IP
        state.ips.insert(normalized_ip);
        Ok(())
    }
}

fn normalize_dual_stack_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            // Convert ::ffff:192.0.2.1 to 192.0.2.1
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpTrackerError {
    #[error("IP limit exceeded for this token ({current_count}/{limit} IPs). Please refresh your token.")]
    LimitExceeded {
        token_id: String,
        current_count: usize,
        limit: usize,
        client_ip: IpAddr,
    },
}
```

**Key Fixes:**
1. ✅ Use `get_mut` + `put` instead of non-existent `get_or_insert_mut`
2. ✅ TTL reset clears IPs but keeps entry (no eviction issue)
3. ✅ No `cleanup_expired` needed (handled inline)
4. ✅ Normalize IP before any checks

---

### 5. Security Monitoring - Bounded with Eviction

**Problems:**
- ❌ Unbounded in-memory maps
- ❌ No eviction or TTL

**Solution:**

```rust
// src/security/leak_detector.rs

pub struct TokenLeakDetector {
    // LRU cache with max 10,000 tokens tracked
    patterns: Arc<Mutex<LruCache<String, RequestPattern>>>,
}

struct RequestPattern {
    unique_destinations: BTreeSet<String>,  // Max 1000 destinations tracked
    unique_ips: BTreeSet<IpAddr>,           // Max 100 IPs tracked
    request_count: usize,
    first_seen: Instant,
}

impl TokenLeakDetector {
    pub fn new() -> Self {
        Self {
            patterns: Arc::new(Mutex::new(
                LruCache::new(NonZeroUsize::new(10_000).unwrap())
            )),
        }
    }

    pub async fn check_for_anomalies(&self, token_id: &str, request: &HttpRequest) -> Vec<SecurityAlert> {
        let mut patterns = self.patterns.lock().await;

        let pattern = match patterns.get_mut(token_id) {
            Some(p) => {
                // TTL check: reset if older than 1 hour
                if p.first_seen.elapsed() > Duration::from_secs(3600) {
                    p.unique_destinations.clear();
                    p.unique_ips.clear();
                    p.request_count = 0;
                    p.first_seen = Instant::now();
                }
                p
            }
            None => {
                patterns.put(token_id.to_string(), RequestPattern {
                    unique_destinations: BTreeSet::new(),
                    unique_ips: BTreeSet::new(),
                    request_count: 0,
                    first_seen: Instant::now(),
                });
                patterns.get_mut(token_id).unwrap()
            }
        };

        // Bounded set insertions
        if pattern.unique_destinations.len() < 1000 {
            pattern.unique_destinations.insert(request.destination.clone());
        }
        if pattern.unique_ips.len() < 100 {
            pattern.unique_ips.insert(request.client_ip);
        }
        pattern.request_count += 1;

        // Anomaly checks (same as before)
        let mut alerts = vec![];
        if pattern.unique_ips.len() > 10 {
            alerts.push(SecurityAlert::SuspiciousIpPattern { /* ... */ });
        }

        alerts
    }
}
```

**Key Fixes:**
1. ✅ LRU cache with max 10,000 tokens
2. ✅ Bounded sets: 1000 destinations, 100 IPs per token
3. ✅ TTL reset after 1 hour (inline, no separate cleanup)

---

### 6. Testing Timeline - Realistic Scope

**Problem:**
- ❌ 160+ tests in 32 hours unrealistic

**Solution: Phased Testing Approach**

**Phase 1 Must-Have (16 hours):**
- Unit tests: 40 tests
  - IP tracker: 8 tests
  - Destination filter: 10 tests
  - Body limiter: 8 tests
  - Header filter: 8 tests
  - Method validator: 6 tests
- Integration tests: 15 tests
  - Basic HTTP GET/POST (local server)
  - Body size limit enforcement
  - IP limit enforcement
  - Destination blocking (RFC1918)
  - TLS connections (https://)
- Load test: 1 scenario (h2load basic throughput)

**Phase 2 Nice-to-Have (16 hours):**
- Integration tests: 35 tests (real servers, edge cases)
- Security tests: 30 tests (SSRF, injection, abuse)
- Load tests: 5 scenarios (concurrency, large bodies)

**Updated Timeline:**
- **Phase 1 (HTTP/1.1 + must-have tests)**: 32 hours
- **Phase 2 (comprehensive testing)**: +16 hours
- **Total**: 48 hours realistic estimate

---

## Open Questions - Answers

### Q1: Should https:// forwarding be in-scope?

**Answer: YES, https:// is in-scope**

**Rationale:**
- Chrome connectivity probes use both http:// and https://
- Most modern sites are HTTPS-only
- Without https:// support, proxy is essentially useless

**Implementation:**
- Use rustls for TLS client
- SNI set to original hostname
- Connect to vetted IP (not hostname)

**Config:**
```bash
HTTP_PROXY_SUPPORT_HTTPS=true  # Default: true
```

### Q2: Behavior for legitimate DNS rotation (CDN)?

**Answer: Allow differing IP sets if all IPs are public**

**Policy:**
- ✅ Allow: All IPs in fresh lookup are public (not in blocklist)
- ❌ Block: ANY IP in fresh lookup is in blocklist
- ✅ Cache: Single lookup, 60s TTL, no re-check

**Example:**
```
Initial lookup: cdn.example.com -> [1.2.3.4, 5.6.7.8]
All public IPs -> ✅ Allowed, cache for 60s
Next request (within 60s) -> Use cached IPs
Next request (after 60s) -> Re-resolve -> [9.10.11.12, 5.6.7.8]
All public IPs -> ✅ Allowed (rotation is fine)
```

**No false positives for CDN/geo DNS rotation.**

---

## Updated Dependencies

```toml
[dependencies]
hyper = { version = "1.0", features = ["full"] }
hyper-util = { version = "0.1", features = ["client"] }
tokio = { version = "1", features = ["full"] }
rustls = "0.23"
tokio-rustls = "0.26"
webpki-roots = "0.26"  # For CA cert verification
trust-dns-resolver = "0.23"
ipnetwork = "0.20"
lru = "0.12"
pin-project = "1.1"
thiserror = "1.0"
```

---

## Summary of Critical Changes

| Issue | Fix |
|-------|-----|
| Connect to hostname | ✅ Connect to vetted IP only |
| No HTTPS support | ✅ rustls + SNI implemented |
| Absolute-form URI | ✅ Origin-form URI + Host header |
| DNS rebinding bypass | ✅ Single lookup, return vetted IPs to caller |
| IPv4-mapped blocked | ✅ Removed `::ffff:0:0/96` from blocklist |
| DNS rotation false positive | ✅ Accept rotation if all IPs public |
| Incomplete body limiter | ✅ Full implementation with pin-project |
| IP tracker API issues | ✅ Use `get_mut`/`put`, normalize IP first |
| Unbounded monitoring | ✅ LRU + bounded sets + TTL |
| Unrealistic timeline | ✅ 32h must-have, +16h nice-to-have |

**Revised Timeline: 48 hours total (32h Phase 1 + 16h Phase 2)**
**Must-Have Tests: 55 tests (Phase 1)**
**Nice-to-Have Tests: +105 tests (Phase 2)**

---

**Next Steps:**
1. Engineering team approval of fixes
2. Confirm https:// in-scope (recommended: YES)
3. Begin Phase 1 implementation (32 hours)
