# Engineering Feedback Response & Updated HTTP Proxy Plan

**Date**: 2025-11-21
**Document Version**: 1.0
**Status**: Architecture Review

---

## Executive Summary

This document addresses critical engineering feedback on the HTTP Proxy Implementation Plan. Key changes include:
- **Simplified HTTP/2 scope** - Focus on HTTP/1.1 only, defer HTTP/2 non-CONNECT
- **Unified tech stack** - Use hyper/h2 exclusively, remove reqwest dependency
- **Enhanced SSRF protection** - DNS rebinding prevention, expanded blocklists
- **Robust IP tracking** - Clear eviction semantics, dual-stack handling
- **User-friendly error messages** - "IP limit exceeded, please refresh token"
- **Realistic performance targets** - Based on Phase 8 learnings
- **Comprehensive header sanitization** - All hop-by-hop headers listed explicitly

---

## 1. Feedback Analysis & Responses

### 1.1 HTTP/2 Forwarding Complexity

**Feedback:**
> HTTP/2 proxying of plain HTTP requests is tricky. Real HTTP/2 proxy requests use pseudo-headers (:scheme, :authority, :path), not absolute URIs. The plan lumps HTTP/1.1 and HTTP/2 forwarding together; be explicit whether you intend to proxy normal HTTP/2 requests (not just CONNECT) and how you'll map pseudo-headers to upstream.

**Analysis:**
- Current plan conflates HTTP/1.1 and HTTP/2 forwarding without addressing protocol differences
- HTTP/2 non-CONNECT forwarding requires pseudo-header mapping: `:method`, `:scheme`, `:authority`, `:path`
- Absolute-form URIs (HTTP/1.1 proxy style) don't directly map to HTTP/2 semantics
- Adds significant complexity for uncertain benefit (Chrome already uses HTTP/1.1 for proxy requests)

**Resolution:**
✅ **SCOPE CHANGE: HTTP/1.1 Only for Initial Release**

**Updated Scope:**
- **Phase 1-4**: Implement HTTP/1.1 forwarding only
- **HTTP/2 CONNECT**: Already working (tunnel mode)
- **HTTP/2 non-CONNECT**: Deferred to Phase 2 (future enhancement)
- **Reasoning**: Chrome connectivity probes and most browser traffic use HTTP/1.1 proxy protocol

**Future HTTP/2 Forwarding (Phase 2):**
```rust
// When implemented, pseudo-header mapping will be:
// :method = GET/POST/etc
// :scheme = http/https
// :authority = host:port
// :path = /path?query
// Body = stream body if present

// Example:
// HTTP/1.1: GET http://example.com/page HTTP/1.1
// HTTP/2:   :method GET
//           :scheme http
//           :authority example.com
//           :path /page
```

**Updated Timeline:**
- Remove Phase 3 (HTTP/2 forwarding) from initial release
- Reduces implementation from 20 hours → 16 hours
- Lower risk, faster delivery

---

### 1.2 Library Choice: reqwest vs hyper

**Feedback:**
> The plan mentions "Build reqwest HTTP client" for upstream in the design, while the codebase uses hyper/h2. Mixing stacks adds overhead and TLS config duplication. Prefer reusing hyper clients/executors or a minimal TCP client for plain HTTP to avoid pulling in another HTTP client with its own TLS stack.

**Analysis:**
- Current plan: Use `reqwest` for upstream HTTP client
- Existing codebase: Uses `hyper` 1.0 + `h2` for CONNECT tunnels
- Problem: `reqwest` bundles its own hyper + rustls/native-tls, duplicating dependencies
- Overhead: Extra TLS stack, extra executor, larger binary size
- Configuration duplication: Timeouts, TLS certs, DNS resolver

**Resolution:**
✅ **USE HYPER EXCLUSIVELY - No reqwest**

**Updated Architecture:**

```rust
// src/http_forwarder.rs

use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

pub async fn forward_http1_request(
    req: Request<Incoming>,
    config: Arc<Config>,
    claims: Claims,
    client_ip: IpAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {

    // 1. Extract target URL from absolute-form URI
    let uri = req.uri();
    let target_host = uri.authority().ok_or(ProxyError::InvalidUri)?;

    // 2. Security checks (destination filter, IP limit, rate limit)
    // ... (unchanged)

    // 3. Connect to upstream using hyper client
    let stream = TcpStream::connect(target_host.as_str()).await?;
    let io = TokioIo::new(stream);

    // 4. Create hyper HTTP/1 client connection
    let (mut sender, conn) = http1::handshake(io).await?;

    // Spawn connection task
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!("HTTP/1 connection error: {}", e);
        }
    });

    // 5. Build upstream request
    let mut upstream_req = Request::builder()
        .method(req.method())
        .uri(req.uri())
        .version(Version::HTTP_11);

    // 6. Copy headers (filtered)
    for (name, value) in req.headers() {
        if !is_hop_by_hop_header(name) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // 7. Forward request
    let upstream_resp = sender.send_request(upstream_req.body(req.into_body())?).await?;

    // 8. Build response
    let mut resp = Response::builder()
        .status(upstream_resp.status())
        .version(Version::HTTP_11);

    // 9. Copy response headers (filtered)
    for (name, value) in upstream_resp.headers() {
        if !is_hop_by_hop_header(name) {
            resp = resp.header(name, value);
        }
    }

    // 10. Stream response body with size limit
    let body = upstream_resp.into_body();
    let limited_body = LimitedBody::new(body, config.max_response_body_size);

    Ok(resp.body(BoxBody::new(limited_body))?)
}
```

**Benefits:**
- **Single TLS stack**: Reuse existing rustls configuration
- **Smaller binary**: No duplicate HTTP client
- **Consistent behavior**: Same timeout/DNS logic as CONNECT
- **Better performance**: Direct hyper usage, no abstraction overhead

**Dependencies (no change needed):**
```toml
# Cargo.toml - Already have these
hyper = { version = "1.0", features = ["full"] }
hyper-util = "0.1"
tokio = { version = "1", features = ["full"] }
# NO reqwest needed
```

---

### 1.3 SSRF & Destination Filtering

**Feedback:**
> Blocking only RFC1918/localhost/metadata is good but not sufficient without DNS-race considerations. Decide whether to filter before and after DNS resolution, cache resolutions safely, and consider blocking link-local IPv6, ULA, and localhost names. "resolve_and_check(host)" needs to guard against rebinding: resolve per request or cache with TTL and recheck IP CIDRs, not just host names.

**Analysis:**
- **DNS Rebinding Attack**: Attacker controls DNS, returns public IP first, then private IP on subsequent lookups
- **Current plan**: Basic IP range blocking, unclear DNS resolution strategy
- **Missing blocklists**: Link-local IPv6 (`fe80::/10`), ULA (`fc00::/7`), localhost names

**Resolution:**
✅ **ENHANCED SSRF PROTECTION WITH DNS REBINDING PREVENTION**

**Updated Destination Filter Strategy:**

```rust
// src/destination_filter.rs

use trust_dns_resolver::TokioAsyncResolver;
use lru::LruCache;
use std::time::{Duration, Instant};

pub struct DestinationFilter {
    resolver: Arc<TokioAsyncResolver>,
    dns_cache: Arc<Mutex<LruCache<String, CachedResolution>>>,
    blocked_ranges: Vec<IpNetwork>,
    blocked_hostnames: HashSet<String>,
}

struct CachedResolution {
    ips: Vec<IpAddr>,
    resolved_at: Instant,
    ttl: Duration,
}

impl DestinationFilter {
    pub async fn check_destination(&self, host: &str) -> Result<(), DestinationError> {
        // 1. Check hostname blocklist (before DNS resolution)
        if self.is_hostname_blocked(host) {
            return Err(DestinationError::BlockedHostname(host.to_string()));
        }

        // 2. Resolve hostname to IPs (with caching)
        let ips = self.resolve_with_cache(host).await?;

        // 3. Check ALL resolved IPs against blocklist
        for ip in &ips {
            if self.is_ip_blocked(*ip) {
                return Err(DestinationError::BlockedIpRange(*ip));
            }
        }

        // 4. RE-RESOLVE before connecting (DNS rebinding protection)
        // Don't cache this - force fresh lookup
        let fresh_ips = self.resolve_fresh(host).await?;

        // 5. Verify fresh IPs match cached IPs
        if !ips_match(&ips, &fresh_ips) {
            warn!("DNS rebinding detected for {}: {:?} -> {:?}", host, ips, fresh_ips);
            return Err(DestinationError::DnsRebinding(host.to_string()));
        }

        // 6. Check fresh IPs against blocklist again
        for ip in &fresh_ips {
            if self.is_ip_blocked(*ip) {
                return Err(DestinationError::BlockedIpRange(*ip));
            }
        }

        Ok(())
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        for range in &self.blocked_ranges {
            if range.contains(ip) {
                return true;
            }
        }
        false
    }

    fn is_hostname_blocked(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Exact match
        if self.blocked_hostnames.contains(&host_lower) {
            return true;
        }

        // Localhost variants
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "ip6-localhost"
            || host_lower == "ip6-loopback" {
            return true;
        }

        false
    }
}

// Expanded blocked IP ranges
const BLOCKED_IP_RANGES: &[&str] = &[
    // IPv4 Private Networks (RFC1918)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",

    // IPv4 Localhost
    "127.0.0.0/8",

    // IPv4 Link-Local
    "169.254.0.0/16",

    // IPv4 Metadata Services
    "169.254.169.254/32",  // AWS, Azure, GCP

    // IPv4 Broadcast/Special
    "0.0.0.0/8",           // Current network
    "255.255.255.255/32",  // Broadcast
    "224.0.0.0/4",         // Multicast
    "240.0.0.0/4",         // Reserved

    // IPv6 Localhost
    "::1/128",

    // IPv6 Link-Local
    "fe80::/10",

    // IPv6 Unique Local Addresses (ULA)
    "fc00::/7",

    // IPv6 Metadata (AWS)
    "fd00:ec2::254/128",

    // IPv6 Documentation/Reserved
    "::ffff:0:0/96",       // IPv4-mapped
    "2001:db8::/32",       // Documentation
    "ff00::/8",            // Multicast
];

// Blocked hostnames (in addition to IP ranges)
const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "metadata.google.internal",          // GCP
    "metadata.azure.com",                // Azure (169.254.169.254)
    "instance-data.ec2.internal",        // AWS (old)
];
```

**DNS Resolution Strategy:**

1. **Initial check**: Resolve hostname, check all IPs against blocklist (cached, 60s TTL)
2. **Pre-connect re-check**: Resolve again (no cache), verify IPs haven't changed
3. **Rebinding detection**: If IPs changed, log warning and reject request
4. **Connect**: Use IPs from fresh resolution only

**Benefits:**
- Prevents DNS rebinding attacks (TOCTOU vulnerability)
- Blocks link-local IPv6 and ULA ranges
- Blocks localhost hostname variants
- Caches resolutions for performance (60s TTL)
- Forces fresh lookup before connecting

**Configuration:**
```bash
# Environment variables
DESTINATION_FILTER_MODE=block              # "block" or "allow"
DESTINATION_FILTER_DNS_TIMEOUT=5           # DNS resolution timeout (seconds)
DESTINATION_FILTER_DNS_CACHE_TTL=60        # Cache TTL (seconds)
DESTINATION_FILTER_RECHECK_BEFORE_CONNECT=true  # DNS rebinding protection
DESTINATION_BLOCKLIST_EXTRA=               # Additional IPs/CIDRs/hostnames
```

---

### 1.4 IP-per-Token Limits

**Feedback:**
> Good anti-abuse lever but needs careful data structure sizing. An LRU of token→HashSet can be memory-heavy; define eviction and TTL semantics clearly. Also decide how to handle dual-stack clients (IPv4+IPv6) and proxies behind NAT.

**Analysis:**
- Current plan: `LruCache<String, HashSet<IpAddr>>` - unclear memory bounds
- Problem: HashSet can grow unbounded per token
- Dual-stack: Same client may use IPv4 and IPv6 (count as 2 IPs?)
- NAT: Multiple users behind NAT share one IP (should allow?)

**Resolution:**
✅ **BOUNDED IP TRACKER WITH CLEAR EVICTION + DUAL-STACK HANDLING**

**Updated IP Tracker Design:**

```rust
// src/ip_tracker.rs

use lru::LruCache;
use std::collections::BTreeSet;  // Ordered set for predictable eviction
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

pub struct IpTracker {
    // LRU cache of token_id -> TokenIpState
    cache: Arc<Mutex<LruCache<String, TokenIpState>>>,

    // Configuration
    max_ips_per_token: usize,        // e.g., 5
    max_tokens_tracked: usize,       // e.g., 10,000
    entry_ttl: Duration,              // e.g., 1 hour
    count_ipv4_ipv6_separately: bool, // Default: false (same client)
}

struct TokenIpState {
    ips: BTreeSet<IpAddr>,           // Bounded by max_ips_per_token
    last_seen: Instant,
    created_at: Instant,
}

impl IpTracker {
    pub fn new(config: &Config) -> Self {
        let max_tokens_tracked = config.ip_tracker_cache_size;

        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(max_tokens_tracked).unwrap()
            ))),
            max_ips_per_token: config.max_ips_per_token,
            max_tokens_tracked,
            entry_ttl: Duration::from_secs(config.ip_tracker_ttl_seconds),
            count_ipv4_ipv6_separately: config.ip_tracker_count_dual_stack,
        }
    }

    pub async fn check_and_track(
        &self,
        token_id: &str,
        client_ip: IpAddr,
    ) -> Result<(), IpTrackerError> {

        let mut cache = self.cache.lock().await;

        // Get or create token state
        let state = cache.get_or_insert_mut(token_id.to_string(), || TokenIpState {
            ips: BTreeSet::new(),
            last_seen: Instant::now(),
            created_at: Instant::now(),
        });

        // Check TTL expiration
        if state.created_at.elapsed() > self.entry_ttl {
            // Reset tracking for this token
            state.ips.clear();
            state.created_at = Instant::now();
        }

        // Normalize IP for dual-stack handling
        let normalized_ip = if self.count_ipv4_ipv6_separately {
            client_ip  // Keep as-is
        } else {
            self.normalize_dual_stack_ip(client_ip)
        };

        // Check if IP already tracked
        if state.ips.contains(&normalized_ip) {
            state.last_seen = Instant::now();
            return Ok(());  // Same IP, allowed
        }

        // Check IP limit
        if state.ips.len() >= self.max_ips_per_token {
            return Err(IpTrackerError::LimitExceeded {
                token_id: token_id.to_string(),
                current_count: state.ips.len(),
                limit: self.max_ips_per_token,
                client_ip: normalized_ip,
            });
        }

        // Add new IP
        state.ips.insert(normalized_ip);
        state.last_seen = Instant::now();

        Ok(())
    }

    /// Normalize IPv6-mapped IPv4 addresses to IPv4
    /// e.g., ::ffff:192.0.2.1 -> 192.0.2.1
    fn normalize_dual_stack_ip(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)  // Convert to IPv4
                } else {
                    IpAddr::V6(v6)  // Keep as IPv6
                }
            }
            IpAddr::V4(v4) => IpAddr::V4(v4),
        }
    }

    pub fn get_ip_count(&self, token_id: &str) -> usize {
        self.cache.lock().unwrap()
            .peek(token_id)
            .map(|state| state.ips.len())
            .unwrap_or(0)
    }

    /// Background cleanup task (runs every 5 minutes)
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();

        // Remove expired entries
        cache.iter_mut()
            .filter(|(_, state)| state.created_at.elapsed() > self.entry_ttl)
            .for_each(|(_, state)| {
                state.ips.clear();
                state.created_at = now;
            });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpTrackerError {
    #[error("IP limit exceeded for token {token_id}: {current_count}/{limit} IPs used. New IP: {client_ip}. Please refresh your token to reset the limit.")]
    LimitExceeded {
        token_id: String,
        current_count: usize,
        limit: usize,
        client_ip: IpAddr,
    },
}
```

**User-Facing Error Message:**

```rust
// In server.rs HTTP handler
if let Err(IpTrackerError::LimitExceeded { .. }) = config.ip_tracker.check_and_track(&claims.token_id, client_ip).await {
    return Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(
            "IP limit exceeded for this token. Please refresh your token to continue.\n\n\
             This proxy limits the number of unique IP addresses per token to prevent abuse. \
             If you are behind a VPN or using multiple networks, please request a new token."
        )))
        .unwrap());
}
```

**Memory Bounds:**
- **Per token**: Max `max_ips_per_token` IPs (e.g., 5 × 16 bytes = 80 bytes)
- **Total tokens**: LRU evicts after `max_tokens_tracked` (e.g., 10,000)
- **Max memory**: 10,000 tokens × 80 bytes = 800 KB (plus overhead)
- **TTL**: Entries reset after 1 hour (configurable)

**Dual-Stack Handling:**
- **Default behavior**: IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) normalized to IPv4
- **Reasoning**: Same client using IPv4 and IPv6 shouldn't count as 2 IPs
- **Configuration**: `IP_TRACKER_COUNT_DUAL_STACK=true` to count separately if needed

**NAT Handling:**
- **Shared IP allowed**: Multiple users behind NAT share one IP, won't trigger limit
- **Reasoning**: IP limit is per-token, not per-IP
- **Alternative**: Could implement per-IP-per-token limit, but adds complexity

**Configuration:**
```bash
MAX_IPS_PER_TOKEN=5                    # Max unique IPs per token
IP_TRACKER_CACHE_SIZE=10000            # Max tokens tracked (LRU eviction)
IP_TRACKER_TTL_SECONDS=3600            # Reset tracking after 1 hour
IP_TRACKER_COUNT_DUAL_STACK=false      # Treat IPv4/IPv6 from same host as one IP
```

---

### 1.5 Body Limits & Timeouts

**Feedback:**
> 10MB request/response limits and 30s timeout may be too low for legitimate downloads/POSTs; ensure configurability and clarify behavior (fail fast vs. stream-and-drop when size exceeded).

**Analysis:**
- 10MB limit: Too low for large file uploads/downloads
- 30s timeout: Too low for slow connections or large transfers
- Behavior unclear: Abort immediately? Stream until limit? Partial response?

**Resolution:**
✅ **CONFIGURABLE LIMITS WITH STREAMING BEHAVIOR**

**Updated Body Handling Strategy:**

```rust
// src/body_limiter.rs

use hyper::body::{Body, Bytes, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct LimitedBody<B> {
    inner: B,
    limit: usize,
    bytes_read: usize,
    behavior: LimitBehavior,
}

pub enum LimitBehavior {
    /// Fail immediately when limit exceeded (default)
    FailFast,
    /// Stream until limit, then close connection
    StreamAndClose,
    /// Stream until limit, then return 413 Payload Too Large
    StreamAndError,
}

impl<B: Body> LimitedBody<B> {
    pub fn new(inner: B, limit: usize) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
            behavior: LimitBehavior::FailFast,
        }
    }

    pub fn with_behavior(mut self, behavior: LimitBehavior) -> Self {
        self.behavior = behavior;
        self
    }
}

impl<B: Body> Body for LimitedBody<B> {
    type Data = Bytes;
    type Error = BodyLimitError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {

        let this = self.as_mut().project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let new_total = *this.bytes_read + data.len();

                    if new_total > *this.limit {
                        // Limit exceeded
                        match this.behavior {
                            LimitBehavior::FailFast => {
                                return Poll::Ready(Some(Err(BodyLimitError::LimitExceeded {
                                    limit: *this.limit,
                                    bytes_read: *this.bytes_read,
                                })));
                            }
                            LimitBehavior::StreamAndClose => {
                                // Allow this frame, then close
                                *this.bytes_read = new_total;
                                Poll::Ready(Some(Ok(frame)))
                                // Next poll will return None
                            }
                            LimitBehavior::StreamAndError => {
                                return Poll::Ready(Some(Err(BodyLimitError::PayloadTooLarge {
                                    limit: *this.limit,
                                })));
                            }
                        }
                    } else {
                        *this.bytes_read = new_total;
                        Poll::Ready(Some(Ok(frame)))
                    }
                } else {
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(BodyLimitError::Upstream(e)))),
            Poll::Pending => Poll::Pending,
        }
    }
}
```

**Configuration:**
```bash
# Body Size Limits (in bytes)
MAX_REQUEST_BODY_SIZE=104857600          # 100MB (increased from 10MB)
MAX_RESPONSE_BODY_SIZE=104857600         # 100MB (increased from 10MB)
BODY_LIMIT_BEHAVIOR=fail_fast            # "fail_fast", "stream_and_close", "stream_and_error"

# Timeouts
HTTP_REQUEST_TIMEOUT_SECONDS=120         # 2 minutes (increased from 30s)
HTTP_CONNECT_TIMEOUT_SECONDS=10          # Connection timeout
HTTP_IDLE_TIMEOUT_SECONDS=30             # Idle connection timeout
```

**Behavior Modes:**

1. **FailFast (default)**: Abort immediately when limit exceeded
   - **Use case**: Prevent resource exhaustion
   - **Error**: 413 Payload Too Large
   - **Client experience**: Upload/download fails

2. **StreamAndClose**: Stream until limit, then close connection
   - **Use case**: Partial downloads acceptable
   - **Error**: Connection closed after limit
   - **Client experience**: Partial response

3. **StreamAndError**: Stream until limit, return error
   - **Use case**: Allow streaming but signal error
   - **Error**: 413 after streaming limit bytes
   - **Client experience**: Partial data + error status

**Recommended Settings:**
- **Request body limit**: 100MB (handles large uploads)
- **Response body limit**: 100MB (handles large downloads)
- **Request timeout**: 120s (handles slow uploads)
- **Behavior**: FailFast (prevent abuse)

---

### 1.6 Hop-by-Hop Header Filtering

**Feedback:**
> Necessary, but also strip Proxy-Connection, Keep-Alive, Transfer-Encoding, Upgrade, Expect headers, and handle chunked encoding correctly. Plan should call out request/response header sanitization in detail.

**Analysis:**
- Current plan: Generic "strip hop-by-hop headers" without comprehensive list
- Missing headers: Proxy-Connection, Keep-Alive, TE, Transfer-Encoding, Upgrade, Expect
- Chunked encoding: Must be handled correctly (don't strip Transfer-Encoding if needed)

**Resolution:**
✅ **COMPREHENSIVE HEADER SANITIZATION WITH EXPLICIT LIST**

**Updated Header Filtering:**

```rust
// src/header_filter.rs

use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;

/// Hop-by-hop headers that MUST be stripped (RFC 7230 § 6.1)
const HOP_BY_HOP_HEADERS: &[&str] = &[
    // Standard hop-by-hop headers
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",

    // Additional proxy-specific headers
    "proxy-connection",      // Non-standard but widely used

    // Headers that should not be forwarded
    "expect",                // 100-continue handling
];

/// Additional headers to strip for security
const SECURITY_STRIP_HEADERS: &[&str] = &[
    "x-forwarded-for",       // Don't leak client IPs
    "x-real-ip",
    "x-client-ip",
    "forwarded",
];

pub fn filter_request_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        let name_lower = name.as_str().to_lowercase();

        // Skip hop-by-hop headers
        if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
            continue;
        }

        // Skip security-sensitive headers
        if SECURITY_STRIP_HEADERS.contains(&name_lower.as_str()) {
            continue;
        }

        // Skip headers listed in Connection header
        if is_connection_header(&headers, &name_lower) {
            continue;
        }

        // Copy header
        filtered.insert(name.clone(), value.clone());
    }

    // Add our own headers
    filtered.insert("via", HeaderValue::from_static("1.1 pinaka-proxy"));

    filtered
}

pub fn filter_response_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();

    for (name, value) in headers {
        let name_lower = name.as_str().to_lowercase();

        // Skip hop-by-hop headers
        if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
            continue;
        }

        // Skip headers listed in Connection header
        if is_connection_header(&headers, &name_lower) {
            continue;
        }

        // Copy header
        filtered.insert(name.clone(), value.clone());
    }

    // Add Via header
    filtered.insert("via", HeaderValue::from_static("1.1 pinaka-proxy"));

    filtered
}

/// Check if header is listed in Connection header
/// e.g., "Connection: upgrade, my-custom-header"
fn is_connection_header(headers: &HeaderMap, header_name: &str) -> bool {
    if let Some(conn_value) = headers.get("connection") {
        if let Ok(conn_str) = conn_value.to_str() {
            return conn_str
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(header_name));
        }
    }
    false
}

/// Handle chunked encoding correctly
pub fn handle_chunked_encoding(headers: &mut HeaderMap, body_size: Option<u64>) {
    // If we know the body size, use Content-Length
    if let Some(size) = body_size {
        headers.remove("transfer-encoding");
        headers.insert("content-length", HeaderValue::from(size));
    } else {
        // Use chunked encoding
        headers.remove("content-length");
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    }
}
```

**Specific Handling:**

1. **Connection header**: Parse and strip all headers it lists
   ```http
   Connection: upgrade, my-header
   # Strip both "upgrade" and "my-header"
   ```

2. **Transfer-Encoding**: Handle chunked correctly
   - If body size known: Use `Content-Length`, remove `Transfer-Encoding`
   - If body size unknown: Use `Transfer-Encoding: chunked`
   - Never forward `Transfer-Encoding` with other values (e.g., `gzip, chunked`)

3. **Expect header**: Don't forward `Expect: 100-continue`
   - Proxy should handle 100-continue locally
   - Don't burden upstream with expectation negotiation

4. **Upgrade header**: Block protocol upgrades
   - HTTP/1.1 → WebSocket upgrades not supported over HTTP proxy
   - Return 501 Not Implemented

5. **Via header**: Add our own Via header
   ```http
   Via: 1.1 pinaka-proxy
   ```

**Security Strip Headers:**
- `X-Forwarded-For`, `X-Real-IP`, `Forwarded`: Don't leak client IPs to upstream
- Reasoning: Proxy should be transparent, not reveal client network info

---

### 1.7 Method Whitelist & Protocol Handling

**Feedback:**
> Blocking TRACE is good, but also consider explicitly handling CONNECT-over-HTTP (should be refused) and OPTIONS/* behavior.

**Analysis:**
- Current plan: Block TRACE, allow standard methods
- Missing: CONNECT-over-HTTP (should be handled by CONNECT tunnel, not HTTP forwarding)
- Missing: OPTIONS * handling (server-wide OPTIONS)

**Resolution:**
✅ **EXPLICIT METHOD HANDLING WITH CONNECT REJECTION**

**Updated Method Validation:**

```rust
// src/method_validator.rs

use hyper::Method;

pub enum MethodValidation {
    Allowed,
    Blocked { reason: &'static str },
}

pub fn validate_http_method(method: &Method, uri: &Uri) -> MethodValidation {
    match method {
        // Allowed methods
        &Method::GET | &Method::HEAD | &Method::POST |
        &Method::PUT | &Method::DELETE | &Method::PATCH => {
            MethodValidation::Allowed
        }

        // OPTIONS: Allowed for specific resources, blocked for server-wide
        &Method::OPTIONS => {
            if uri.path() == "*" {
                MethodValidation::Blocked {
                    reason: "Server-wide OPTIONS (*) not supported by proxy"
                }
            } else {
                MethodValidation::Allowed
            }
        }

        // CONNECT: Should use CONNECT tunnel, not HTTP forwarding
        &Method::CONNECT => {
            MethodValidation::Blocked {
                reason: "CONNECT method must use HTTP CONNECT tunnel, not HTTP forwarding"
            }
        }

        // TRACE: Security risk (XST attack)
        &Method::TRACE => {
            MethodValidation::Blocked {
                reason: "TRACE method blocked for security (XST attack prevention)"
            }
        }

        // Unknown methods: Block by default
        _ => {
            MethodValidation::Blocked {
                reason: "Method not allowed by proxy"
            }
        }
    }
}
```

**HTTP Method Behavior:**

| Method | Allowed? | Notes |
|--------|----------|-------|
| GET | ✅ Yes | Standard retrieval |
| HEAD | ✅ Yes | Metadata retrieval |
| POST | ✅ Yes | Form submission, API calls |
| PUT | ✅ Yes | Resource updates |
| DELETE | ✅ Yes | Resource deletion |
| PATCH | ✅ Yes | Partial updates |
| OPTIONS | ⚠️ Conditional | Allowed for `/path`, blocked for `*` |
| CONNECT | ❌ No | Use CONNECT tunnel instead |
| TRACE | ❌ No | Security risk (XST) |
| Unknown | ❌ No | Block by default |

**Error Responses:**

```rust
// In server.rs
match validate_http_method(req.method(), req.uri()) {
    MethodValidation::Allowed => {
        // Proceed with forwarding
    }
    MethodValidation::Blocked { reason } => {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Allow", "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS")
            .body(Full::new(Bytes::from(format!(
                "Method not allowed: {}\n", reason
            ))))
            .unwrap());
    }
}
```

---

### 1.8 Logging & PII

**Feedback:**
> Forwarding HTTP means you'll see full URLs and possibly bodies. Make sure logging defaults avoid capturing sensitive data unless explicitly enabled.

**Analysis:**
- Current plan: "Log all HTTP requests" - unclear what data is logged
- Risk: URLs may contain sensitive data (auth tokens, PII)
- Risk: Request/response bodies may contain passwords, API keys

**Resolution:**
✅ **PII-SAFE LOGGING WITH EXPLICIT OPT-IN FOR SENSITIVE DATA**

**Updated Logging Strategy:**

```rust
// src/request_logger.rs

use url::Url;

pub struct SafeRequestLogger {
    log_urls: bool,
    log_query_params: bool,
    log_headers: bool,
    log_bodies: bool,
    sensitive_headers: HashSet<String>,
}

impl SafeRequestLogger {
    pub async fn log_http_request(
        &self,
        token_id: String,
        user_id: i32,
        method: String,
        full_url: String,
        status: Option<u16>,
        bytes_transferred: i64,
        duration_ms: Option<i64>,
        blocked: bool,
        error: Option<String>,
    ) {
        // Safe fields (always logged)
        let mut log_entry = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "token_id": token_id,
            "user_id": user_id,
            "method": method,
            "status": status,
            "bytes_transferred": bytes_transferred,
            "duration_ms": duration_ms,
            "blocked": blocked,
            "error": error,
        });

        // URL logging (sanitized by default)
        if self.log_urls {
            if let Ok(parsed_url) = Url::parse(&full_url) {
                log_entry["url_scheme"] = json!(parsed_url.scheme());
                log_entry["url_host"] = json!(parsed_url.host_str());
                log_entry["url_path"] = json!(parsed_url.path());

                // Query params: opt-in only
                if self.log_query_params {
                    log_entry["url_query"] = json!(parsed_url.query());
                } else {
                    log_entry["url_query"] = json!("<redacted>");
                }
            }
        } else {
            // Just log host
            if let Ok(parsed_url) = Url::parse(&full_url) {
                log_entry["url_host"] = json!(parsed_url.host_str());
            }
        }

        info!("HTTP request: {}", serde_json::to_string(&log_entry).unwrap());
    }

    /// Sanitize URL for logging (remove query params, fragments)
    fn sanitize_url(&self, url: &str) -> String {
        if let Ok(parsed) = Url::parse(url) {
            let mut sanitized = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            if let Some(port) = parsed.port() {
                sanitized.push_str(&format!(":{}", port));
            }
            sanitized.push_str(parsed.path());
            sanitized
        } else {
            "<invalid-url>".to_string()
        }
    }

    /// Check if header contains sensitive data
    fn is_sensitive_header(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.sensitive_headers.contains(&name_lower)
            || name_lower.contains("auth")
            || name_lower.contains("token")
            || name_lower.contains("key")
            || name_lower.contains("secret")
            || name_lower.contains("password")
            || name_lower.contains("cookie")
    }
}

// Default sensitive headers
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
];
```

**Configuration:**
```bash
# Logging Configuration
LOG_HTTP_REQUESTS=true                  # Enable request logging
LOG_HTTP_URLS=true                      # Log sanitized URLs (no query params)
LOG_HTTP_QUERY_PARAMS=false             # Log query params (PII risk - disabled by default)
LOG_HTTP_HEADERS=false                  # Log headers (PII risk - disabled by default)
LOG_HTTP_BODIES=false                   # Log request/response bodies (HIGH PII RISK - disabled by default)
LOG_HTTP_ERRORS=true                    # Log error messages
```

**Default Logging (Safe):**
```json
{
  "timestamp": "2025-11-21T12:34:56Z",
  "token_id": "tok_abc123",
  "user_id": 42,
  "method": "GET",
  "url_scheme": "https",
  "url_host": "api.example.com",
  "url_path": "/v1/users",
  "url_query": "<redacted>",
  "status": 200,
  "bytes_transferred": 1024,
  "duration_ms": 145,
  "blocked": false
}
```

**Opt-In Logging (PII Risk):**
```json
{
  // ... same as above ...
  "url_query": "user_id=12345&email=user@example.com",  // Enabled with LOG_HTTP_QUERY_PARAMS=true
  "request_headers": {                                   // Enabled with LOG_HTTP_HEADERS=true
    "user-agent": "Mozilla/5.0...",
    "authorization": "<redacted>",                      // Always redacted
    "cookie": "<redacted>"                              // Always redacted
  },
  "request_body": "{\"password\": \"...\"}"             // Enabled with LOG_HTTP_BODIES=true
}
```

**Key Principles:**
1. **Safe by default**: Don't log PII without explicit opt-in
2. **Query params redacted**: May contain auth tokens, PII
3. **Headers redacted**: Authorization, cookies always hidden
4. **Bodies never logged**: Unless explicitly enabled (testing only)
5. **Error messages safe**: Don't include sensitive data

---

### 1.9 Performance Targets

**Feedback:**
> The plan repeats "<100ms overhead" and "1000 req/s" without clarifying test conditions (local upstream vs. Internet). Align targets with realistic workloads to avoid a repeat of Phase 8 mismatched expectations.

**Analysis:**
- Current plan: Vague "< 100ms overhead" without defining baseline
- Phase 8 lessons: Need to specify test conditions, realistic workloads
- Overhead vs. latency: Need to separate proxy overhead from network latency

**Resolution:**
✅ **REALISTIC PERFORMANCE TARGETS WITH TEST CONDITIONS**

**Updated Performance Requirements:**

| Metric | Target | Test Conditions | Rationale |
|--------|--------|-----------------|-----------|
| **Proxy Overhead** | < 10ms (p50), < 50ms (p99) | Local upstream (nginx on localhost) | Time added by proxy processing |
| **End-to-End Latency** | < 200ms (p50), < 1s (p99) | Internet upstream (google.com) | Includes network + proxy |
| **Throughput** | 500 req/s per CPU core | Keep-alive connections, 1KB responses | Proxy processing capacity |
| **Concurrent Connections** | 1000 per instance | Mixed HTTP/HTTPS traffic | Connection handling |
| **Memory per Request** | < 500KB (p50), < 5MB (p99) | 100KB request/response bodies | Memory efficiency |
| **Connection Reuse** | > 80% of requests | HTTP/1.1 keep-alive enabled | Connection pooling |

**Test Scenarios:**

1. **Baseline Performance (Local Upstream)**
   ```bash
   # Setup: nginx on localhost:8080 serving static 1KB file
   # Tool: h2load with keep-alive
   # Measure: Proxy processing overhead only

   h2load -n 10000 -c 100 \
     --proxy http://localhost:8443 \
     --header "Proxy-Authorization: Bearer $TOKEN" \
     http://localhost:8080/test.html

   # Target: 500+ req/s, < 10ms p50 latency
   ```

2. **Internet Performance (Real Upstream)**
   ```bash
   # Setup: Public websites (google.com, example.com)
   # Tool: Custom benchmark with retry logic
   # Measure: End-to-end including network latency

   ./bench_real_world.sh --duration 60s --concurrency 50

   # Target: < 200ms p50 latency (network dependent)
   ```

3. **Large Body Streaming**
   ```bash
   # Setup: 10MB file upload/download
   # Tool: curl with speed limit
   # Measure: Memory usage, streaming efficiency

   curl --proxy http://localhost:8443 \
     --proxy-header "Proxy-Authorization: Bearer $TOKEN" \
     --data-binary @10MB.bin \
     https://httpbin.org/post

   # Target: < 5MB proxy memory usage (streaming, not buffering)
   ```

4. **Concurrent Connections**
   ```bash
   # Setup: 1000 parallel curl requests
   # Tool: GNU parallel
   # Measure: Connection handling, rate limiting

   seq 1 1000 | parallel -j 100 \
     curl --proxy http://localhost:8443 \
     --proxy-header "Proxy-Authorization: Bearer $TOKEN" \
     https://httpbin.org/uuid

   # Target: All requests succeed, < 1s p99 latency
   ```

**Benchmarking Tools:**

```rust
// benches/http_proxy_realistic.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_proxy_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_overhead");

    // Test with local nginx upstream
    for body_size in [1024, 10240, 102400] {  // 1KB, 10KB, 100KB
        group.bench_with_input(
            BenchmarkId::from_parameter(body_size),
            &body_size,
            |b, &size| {
                b.iter(|| {
                    // HTTP request through proxy to localhost:8080
                    black_box(make_proxy_request(size));
                });
            },
        );
    }

    group.finish();
}

fn bench_connection_reuse(c: &mut Criterion) {
    c.bench_function("connection_reuse", |b| {
        let client = setup_keepalive_client();

        b.iter(|| {
            // Make 100 requests with same connection
            for _ in 0..100 {
                black_box(client.get("http://localhost:8080/test").send());
            }
        });
    });
}

criterion_group!(benches, bench_proxy_overhead, bench_connection_reuse);
criterion_main!(benches);
```

**Performance Monitoring (Production):**

```rust
// Prometheus metrics
http_proxy_request_duration_seconds{percentile="p50"} < 0.200
http_proxy_request_duration_seconds{percentile="p99"} < 1.000
http_proxy_throughput_requests_per_second > 100
http_proxy_memory_bytes{percentile="p99"} < 5242880  // 5MB
http_proxy_connection_reuse_rate > 0.80
```

**Key Changes from Original Plan:**
- **Lower overhead target**: 10ms p50 (was 100ms) for local upstream
- **Realistic throughput**: 500 req/s per core (was 1000 req/s, unclear conditions)
- **Defined test conditions**: Local vs. Internet, body sizes, concurrency
- **Multiple metrics**: Not just latency, but memory, connection reuse, throughput
- **Percentiles**: p50 and p99 (not just average)

---

### 1.10 Testing Realism

**Feedback:**
> 100+ tests and benches are outlined, but HTTP forwarding correctness (chunked, 1xx responses, redirect handling, connection reuse) is non-trivial. Budget more time for integration tests with real HTTP servers and race conditions.

**Analysis:**
- Current plan: 100+ tests, but many are unit tests for isolated components
- Missing: Real HTTP servers (nginx, apache), edge cases (chunked, 1xx, redirects)
- Missing: Race condition testing (concurrent requests, connection reuse)

**Resolution:**
✅ **COMPREHENSIVE INTEGRATION TESTING WITH REAL SERVERS**

**Updated Testing Strategy:**

```rust
// tests/integration/real_servers.rs

use testcontainers::{clients::Cli, Container, images::generic::GenericImage};

struct TestEnvironment<'a> {
    docker: Cli,
    nginx: Container<'a, GenericImage>,
    httpbin: Container<'a, GenericImage>,
    proxy: ProxyServer,
}

impl<'a> TestEnvironment<'a> {
    fn setup() -> Self {
        let docker = Cli::default();

        // Start nginx container (for static files, chunked encoding)
        let nginx = docker.run(GenericImage::new("nginx", "alpine")
            .with_exposed_port(80)
            .with_volume("./test-data/nginx.conf", "/etc/nginx/nginx.conf"));

        // Start httpbin container (for POST, redirects, status codes)
        let httpbin = docker.run(GenericImage::new("kennethreitz/httpbin", "latest")
            .with_exposed_port(80));

        // Start proxy server
        let proxy = ProxyServer::start_test_server().await;

        Self { docker, nginx, httpbin, proxy }
    }
}

#[tokio::test]
async fn test_chunked_encoding_transfer() {
    let env = TestEnvironment::setup();

    // nginx configured to send chunked response
    let resp = env.proxy.client()
        .get(env.nginx.url("/chunked-test"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("transfer-encoding"), Some(&"chunked".parse().unwrap()));

    let body = resp.text().await.unwrap();
    assert_eq!(body.len(), 10000);  // Full body received
}

#[tokio::test]
async fn test_100_continue_handling() {
    let env = TestEnvironment::setup();

    // Send request with Expect: 100-continue
    let resp = env.proxy.client()
        .post(env.httpbin.url("/post"))
        .header("Expect", "100-continue")
        .body("large body data...")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_redirect_following() {
    let env = TestEnvironment::setup();

    // httpbin returns 302 redirect
    let resp = env.proxy.client()
        .get(env.httpbin.url("/redirect/3"))
        .send()
        .await
        .unwrap();

    // Client should follow redirects
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.url().path(), "/get");
}

#[tokio::test]
async fn test_connection_reuse_under_load() {
    let env = TestEnvironment::setup();

    // Make 1000 requests with keep-alive
    let client = env.proxy.client_with_keepalive();

    let start = Instant::now();
    let mut tasks = vec![];

    for _ in 0..1000 {
        let client = client.clone();
        let url = env.httpbin.url("/uuid");
        tasks.push(tokio::spawn(async move {
            client.get(&url).send().await
        }));
    }

    let results = futures::future::join_all(tasks).await;
    let duration = start.elapsed();

    // All requests succeed
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1000);

    // Performance check
    assert!(duration < Duration::from_secs(10), "1000 requests took {:?}", duration);

    // Connection reuse check (should use < 100 connections for 1000 requests)
    let connections_used = env.proxy.get_connection_count().await;
    assert!(connections_used < 100, "Too many connections: {}", connections_used);
}

#[tokio::test]
async fn test_concurrent_requests_same_token() {
    let env = TestEnvironment::setup();

    // 100 concurrent requests from same token
    let mut tasks = vec![];
    for _ in 0..100 {
        let client = env.proxy.client();
        let url = env.httpbin.url("/uuid");
        tasks.push(tokio::spawn(async move {
            client.get(&url).send().await
        }));
    }

    let results = futures::future::join_all(tasks).await;

    // All succeed (no race conditions in IP tracking)
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 100);
}

#[tokio::test]
async fn test_race_condition_ip_limit() {
    let env = TestEnvironment::setup();

    // Try to bypass IP limit with concurrent requests
    let token = env.proxy.create_token_with_limit(3);  // Max 3 IPs

    // 10 concurrent requests from 10 different IPs
    let mut tasks = vec![];
    for i in 0..10 {
        let client = env.proxy.client_from_ip(format!("192.0.2.{}", i));
        let url = env.httpbin.url("/uuid");
        tasks.push(tokio::spawn(async move {
            client.get(&url).send().await
        }));
    }

    let results = futures::future::join_all(tasks).await;

    // Only 3 succeed (IP limit enforced atomically)
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 7);
}

#[tokio::test]
async fn test_http_server_compatibility() {
    // Test against multiple HTTP server implementations
    let servers = vec![
        ("nginx", "nginx:alpine"),
        ("apache", "httpd:alpine"),
        ("caddy", "caddy:alpine"),
    ];

    for (name, image) in servers {
        let container = docker.run(GenericImage::new(image, "latest"));

        // Basic GET request
        let resp = proxy.client()
            .get(container.url("/index.html"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200, "Failed with {}", name);
    }
}
```

**Edge Case Testing:**

```rust
// tests/integration/edge_cases.rs

#[tokio::test]
async fn test_zero_length_body() {
    // POST with Content-Length: 0
}

#[tokio::test]
async fn test_missing_content_length() {
    // POST without Content-Length or Transfer-Encoding
}

#[tokio::test]
async fn test_invalid_chunked_encoding() {
    // Malformed chunked response from upstream
}

#[tokio::test]
async fn test_1xx_informational_responses() {
    // 100 Continue, 103 Early Hints
}

#[tokio::test]
async fn test_304_not_modified() {
    // No body, but Content-Length present
}

#[tokio::test]
async fn test_head_request_with_content_length() {
    // HEAD response has Content-Length but no body
}

#[tokio::test]
async fn test_connection_close_mid_stream() {
    // Upstream closes connection while streaming
}

#[tokio::test]
async fn test_slow_client_slow_server() {
    // Both client and server slow, test timeouts
}

#[tokio::test]
async fn test_unicode_in_url() {
    // Non-ASCII characters in URL
}

#[tokio::test]
async fn test_multiple_host_headers() {
    // Malicious request with duplicate Host headers
}
```

**Updated Timeline:**
- **Integration testing**: 8 hours (was 3 hours)
- **Total implementation**: 24 hours (was 20 hours)

**Test Coverage Goals:**
- **Unit tests**: 70+ tests (isolated logic)
- **Integration tests**: 50+ tests (real servers, edge cases)
- **Load tests**: 10+ scenarios (concurrency, throughput)
- **Security tests**: 30+ tests (SSRF, abuse, injection)
- **Total**: 160+ tests

---

### 1.11 Risk of Open Proxy

**Feedback:**
> Even with JWT and IP limits, adding full HTTP forwarding greatly increases the blast radius if a token leaks. Consider an allowlist mode by default or at least mandatory blocklists for private/metadata ranges, plus monitoring/alerting that actually runs in prod.

**Analysis:**
- Risk: Leaked JWT token could be used as open proxy
- Impact: Higher with HTTP forwarding vs. CONNECT only
- Current mitigations: JWT + IP limits + rate limits
- Missing: Production monitoring, alerting, token revocation

**Resolution:**
✅ **DEFENSE IN DEPTH: ALLOWLIST MODE + MONITORING + REVOCATION**

**Updated Security Architecture:**

```rust
// src/config.rs - Security modes

pub enum ProxySecurityMode {
    /// Block mode: Block private IPs, allow public (default)
    BlockPrivate,

    /// Allowlist mode: Only allow specific domains (highest security)
    Allowlist { domains: HashSet<String> },

    /// Strict mode: Allowlist + additional restrictions
    Strict {
        domains: HashSet<String>,
        max_ips_per_token: usize,
        max_requests_per_token_per_hour: usize,
    },
}

impl Config {
    pub fn from_env() -> Self {
        let security_mode = match env::var("PROXY_SECURITY_MODE").unwrap_or_default().as_str() {
            "allowlist" => {
                let domains = env::var("PROXY_ALLOWLIST_DOMAINS")
                    .expect("PROXY_ALLOWLIST_DOMAINS required in allowlist mode")
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect();
                ProxySecurityMode::Allowlist { domains }
            }
            "strict" => {
                let domains = env::var("PROXY_ALLOWLIST_DOMAINS")
                    .expect("PROXY_ALLOWLIST_DOMAINS required in strict mode")
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect();
                ProxySecurityMode::Strict {
                    domains,
                    max_ips_per_token: env::var("MAX_IPS_PER_TOKEN")
                        .unwrap_or_else(|_| "3".to_string())
                        .parse().unwrap(),
                    max_requests_per_token_per_hour: env::var("MAX_REQUESTS_PER_TOKEN_PER_HOUR")
                        .unwrap_or_else(|_| "1000".to_string())
                        .parse().unwrap(),
                }
            }
            _ => ProxySecurityMode::BlockPrivate,  // Default
        };

        Self {
            security_mode,
            // ... other fields
        }
    }
}
```

**Configuration Options:**

```bash
# Security Mode
PROXY_SECURITY_MODE=block_private        # "block_private", "allowlist", "strict"

# Allowlist Mode (PROXY_SECURITY_MODE=allowlist or strict)
PROXY_ALLOWLIST_DOMAINS=example.com,api.example.com,cdn.example.com

# Strict Mode Additional Limits (PROXY_SECURITY_MODE=strict)
MAX_IPS_PER_TOKEN=3                      # Lower limit in strict mode
MAX_REQUESTS_PER_TOKEN_PER_HOUR=1000     # Hourly rate limit per token

# Monitoring
ENABLE_TOKEN_LEAK_DETECTION=true         # Anomaly detection
TOKEN_LEAK_ALERT_WEBHOOK=https://alerts.probeops.com/webhook
TOKEN_AUTO_REVOCATION=true               # Auto-revoke suspicious tokens

# Mandatory Blocklists (always active)
BLOCK_PRIVATE_IPS=true                   # Cannot be disabled
BLOCK_METADATA_IPS=true                  # Cannot be disabled
```

**Token Leak Detection:**

```rust
// src/security/leak_detector.rs

pub struct TokenLeakDetector {
    request_patterns: Arc<Mutex<HashMap<String, RequestPattern>>>,
}

struct RequestPattern {
    unique_destinations: HashSet<String>,
    unique_ips: HashSet<IpAddr>,
    request_count: usize,
    first_seen: Instant,
    last_seen: Instant,
}

impl TokenLeakDetector {
    pub async fn check_for_anomalies(&self, token_id: &str, request: &HttpRequest) -> SecurityAlert {
        let mut patterns = self.request_patterns.lock().await;
        let pattern = patterns.entry(token_id.to_string()).or_insert_with(|| RequestPattern::new());

        pattern.unique_destinations.insert(request.destination.clone());
        pattern.unique_ips.insert(request.client_ip);
        pattern.request_count += 1;
        pattern.last_seen = Instant::now();

        // Anomaly detection heuristics
        let alerts = vec![];

        // 1. Too many unique IPs in short time (token sharing)
        if pattern.unique_ips.len() > 10 && pattern.first_seen.elapsed() < Duration::from_secs(300) {
            alerts.push(SecurityAlert::SuspiciousIpPattern {
                token_id: token_id.to_string(),
                ip_count: pattern.unique_ips.len(),
                time_window: pattern.first_seen.elapsed(),
            });
        }

        // 2. Too many unique destinations (scanning behavior)
        if pattern.unique_destinations.len() > 100 {
            alerts.push(SecurityAlert::ScanningBehavior {
                token_id: token_id.to_string(),
                destination_count: pattern.unique_destinations.len(),
            });
        }

        // 3. High request rate (abuse)
        let rate = pattern.request_count as f64 / pattern.first_seen.elapsed().as_secs_f64();
        if rate > 10.0 {  // 10 req/s
            alerts.push(SecurityAlert::HighRequestRate {
                token_id: token_id.to_string(),
                rate,
            });
        }

        // 4. Access to unusual ports (not 80/443)
        if !matches!(request.destination_port, 80 | 443 | 8080 | 8443) {
            alerts.push(SecurityAlert::UnusualPort {
                token_id: token_id.to_string(),
                port: request.destination_port,
            });
        }

        if !alerts.is_empty() {
            self.send_alerts(&alerts).await;
        }

        alerts
    }

    async fn send_alerts(&self, alerts: &[SecurityAlert]) {
        // Send to monitoring webhook
        // Log to security audit log
        // Auto-revoke token if configured
    }
}
```

**Production Monitoring:**

```rust
// Prometheus metrics for security monitoring

// Token usage patterns
http_proxy_unique_ips_per_token{token_id="tok_abc"} = 5
http_proxy_unique_destinations_per_token{token_id="tok_abc"} = 42
http_proxy_requests_per_hour{token_id="tok_abc"} = 350

// Security alerts
http_proxy_security_alerts_total{type="suspicious_ip_pattern"} = 3
http_proxy_security_alerts_total{type="scanning_behavior"} = 1
http_proxy_blocked_requests_total{reason="private_ip"} = 127
http_proxy_blocked_requests_total{reason="metadata_ip"} = 5

// Token revocations
http_proxy_tokens_revoked_total{reason="anomaly_detection"} = 2
http_proxy_tokens_revoked_total{reason="manual"} = 1
```

**Alerting Rules:**

```yaml
# Prometheus alerting rules
groups:
  - name: proxy_security
    rules:
      # Token leak suspected
      - alert: TokenLeakSuspected
        expr: http_proxy_unique_ips_per_token > 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Token {{ $labels.token_id }} used from {{ $value }} unique IPs"

      # Scanning behavior detected
      - alert: ScanningBehaviorDetected
        expr: rate(http_proxy_unique_destinations_per_token[5m]) > 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Token {{ $labels.token_id }} accessing many unique destinations"

      # High blocked request rate (attempted abuse)
      - alert: HighBlockedRequestRate
        expr: rate(http_proxy_blocked_requests_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate of blocked requests: {{ $value }}/s"
```

**Token Revocation API:**

```rust
// Backend API endpoint for emergency token revocation

// POST /api/proxy-tokens/{token_id}/revoke
pub async fn revoke_token(
    token_id: Path<String>,
    reason: Json<RevocationReason>,
) -> Result<StatusCode, ApiError> {

    // Mark token as revoked in database
    db::proxy_tokens::revoke(&token_id, &reason.reason).await?;

    // Notify all proxy instances via Redis pub/sub
    redis.publish("token_revocations", json!({
        "token_id": token_id,
        "revoked_at": Utc::now(),
        "reason": reason.reason,
    })).await?;

    // Log security event
    audit_log::log_token_revocation(&token_id, &reason.reason).await;

    Ok(StatusCode::NO_CONTENT)
}
```

**Key Mitigation Layers:**

1. **JWT Authentication**: First line of defense
2. **IP Limits**: Prevent token sharing (5 IPs per token)
3. **Rate Limits**: Prevent abuse (10,000 req/min per token)
4. **Destination Filtering**: Block private IPs (mandatory, cannot disable)
5. **Allowlist Mode**: Only specific domains (optional, highest security)
6. **Anomaly Detection**: Detect suspicious patterns
7. **Monitoring & Alerting**: Real-time security visibility
8. **Token Revocation**: Emergency kill switch

**Recommended Configuration for Production:**

```bash
# Strict mode for highest security
PROXY_SECURITY_MODE=strict
PROXY_ALLOWLIST_DOMAINS=api.example.com,cdn.example.com
MAX_IPS_PER_TOKEN=3
MAX_REQUESTS_PER_TOKEN_PER_HOUR=1000
ENABLE_TOKEN_LEAK_DETECTION=true
TOKEN_AUTO_REVOCATION=true
```

---

## 2. Revised Implementation Plan

### 2.1 Updated Scope

**IN SCOPE (Phase 1):**
- ✅ HTTP/1.1 forwarding (GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS)
- ✅ JWT authentication (reuse existing)
- ✅ IP-per-token limits with user-friendly error messages
- ✅ Destination filtering with DNS rebinding protection
- ✅ Body size limits (configurable, 100MB default)
- ✅ Request timeouts (configurable, 120s default)
- ✅ Hop-by-hop header filtering (comprehensive list)
- ✅ PII-safe logging
- ✅ Security monitoring and alerting
- ✅ Token leak detection

**OUT OF SCOPE (Deferred to Phase 2):**
- ❌ HTTP/2 non-CONNECT forwarding (complex pseudo-header mapping)
- ❌ WebSocket upgrades over HTTP proxy
- ❌ HTTP/3 (QUIC) support

### 2.2 Updated Timeline

| Phase | Duration | Tasks |
|-------|----------|-------|
| **Phase 1: Foundation** | 5 hours | IP tracker, destination filter (DNS rebinding), config |
| **Phase 2: HTTP/1.1 Forwarding** | 8 hours | Core forwarding with hyper (not reqwest) |
| **Phase 3: Security Hardening** | 5 hours | Header filtering, body limits, method validation |
| **Phase 4: Monitoring & Detection** | 3 hours | Anomaly detection, alerting, revocation |
| **Phase 5: Testing & Integration** | 8 hours | Real servers, edge cases, load testing |
| **Phase 6: Documentation & Deployment** | 3 hours | Docs, deployment guide, runbooks |
| **Total** | **32 hours** | (was 20 hours, now realistic) |

### 2.3 Updated Dependencies

```toml
# Cargo.toml - No reqwest, use hyper exclusively

[dependencies]
# Existing dependencies (no changes)
hyper = { version = "1.0", features = ["full"] }
hyper-util = "0.1"
h2 = "0.4"
tokio = { version = "1", features = ["full"] }
rustls = "0.21"

# New dependencies for HTTP proxy
ipnetwork = "0.20"                    # CIDR parsing for destination filter
trust-dns-resolver = "0.23"           # DNS resolution with caching
lru = "0.12"                          # LRU cache for IP tracker
thiserror = "1.0"                     # Error handling

# Testing
[dev-dependencies]
testcontainers = "0.15"               # Docker containers for integration tests
criterion = "0.5"                     # Benchmarking
```

### 2.4 File Structure

```
pinaka-rust-proxy/
├── src/
│   ├── main.rs
│   ├── server.rs                    # Modified: HTTP forwarding handler
│   ├── config.rs                    # Modified: New config fields
│   ├── http_forwarder.rs            # NEW: HTTP/1.1 forwarding logic (hyper)
│   ├── ip_tracker.rs                # NEW: IP-per-token tracking with LRU
│   ├── destination_filter.rs        # NEW: SSRF protection + DNS rebinding
│   ├── header_filter.rs             # NEW: Hop-by-hop header sanitization
│   ├── method_validator.rs          # NEW: HTTP method whitelist
│   ├── body_limiter.rs              # NEW: Body size limiting with streaming
│   ├── security/
│   │   ├── mod.rs
│   │   └── leak_detector.rs         # NEW: Token leak detection
│   └── lib.rs                       # Modified: Export new modules
├── tests/
│   ├── integration/
│   │   ├── real_servers.rs          # NEW: nginx, httpd, httpbin tests
│   │   ├── edge_cases.rs            # NEW: Chunked, 1xx, redirects
│   │   └── security_tests.rs        # NEW: SSRF, injection, abuse
│   └── load/
│       └── http_proxy_load.rs       # NEW: Load testing scenarios
├── benches/
│   └── http_proxy_realistic.rs      # NEW: Realistic benchmarks
├── docs/
│   ├── HTTP_PROXY_IMPLEMENTATION_PLAN.md       # This document (updated)
│   ├── ENGINEERING_FEEDBACK_RESPONSE.md        # This document
│   ├── HTTP_PROXY_SECURITY.md                  # NEW: Security architecture
│   └── HTTP_PROXY_OPERATIONS.md                # NEW: Production runbook
└── Cargo.toml                       # Modified: New dependencies
```

---

## 3. Summary of Key Changes

### 3.1 Architecture Improvements

| Issue | Original Plan | Updated Solution |
|-------|---------------|------------------|
| HTTP/2 Complexity | Mixed HTTP/1.1 and HTTP/2 | **HTTP/1.1 only** for initial release |
| Library Choice | reqwest for upstream | **hyper exclusively** (reuse existing stack) |
| SSRF Protection | Basic IP blocking | **DNS rebinding protection** + expanded blocklists |
| IP Tracking | Unclear eviction | **Bounded LRU** with clear TTL semantics |
| Dual-Stack Handling | Not addressed | **IPv6-mapped IPv4 normalization** |
| Error Messages | Generic errors | **User-friendly**: "IP limit exceeded, please refresh token" |
| Body Limits | Fixed 10MB | **Configurable 100MB** with streaming behavior |
| Timeouts | Fixed 30s | **Configurable 120s** with separate connect timeout |
| Header Filtering | Generic "hop-by-hop" | **Explicit list** of all headers to strip |
| Method Handling | Basic whitelist | **Explicit CONNECT rejection** + OPTIONS/* handling |
| Logging | "Log all requests" | **PII-safe by default**, opt-in for sensitive data |
| Performance Targets | Vague "< 100ms" | **Realistic: 10ms p50 overhead**, defined test conditions |
| Testing | 100+ unit tests | **160+ tests** including real servers, edge cases, 8 hours testing |
| Security | JWT + IP limits | **Defense in depth**: allowlist mode, monitoring, revocation |

### 3.2 Timeline Changes

- **Original**: 20 hours
- **Updated**: 32 hours (+60% for realism)
- **Key additions**:
  - +3 hours for monitoring/detection
  - +5 hours for integration testing
  - +2 hours for DNS rebinding protection
  - +2 hours for comprehensive header filtering

### 3.3 Risk Mitigation

**Original Plan Risks:**
1. HTTP/2 pseudo-header complexity underestimated
2. reqwest adding dependency bloat
3. DNS rebinding vulnerability
4. Unbounded memory in IP tracker
5. Fixed limits too restrictive
6. Missing production monitoring
7. Token leak undetected

**Updated Mitigations:**
1. ✅ Defer HTTP/2 to Phase 2
2. ✅ Use hyper exclusively
3. ✅ Resolve hostname before AND after caching
4. ✅ Bounded LRU with clear TTL
5. ✅ Configurable limits (100MB, 120s)
6. ✅ Prometheus metrics + alerting
7. ✅ Anomaly detection + auto-revocation

---

## 4. Next Steps

### 4.1 Pre-Implementation

- [ ] Review this document with engineering team
- [ ] Approve updated scope (HTTP/1.1 only initially)
- [ ] Approve 32-hour timeline
- [ ] Decide on security mode for production (recommend: strict)
- [ ] Set up monitoring infrastructure (Prometheus + Grafana)

### 4.2 Implementation Order

1. **Week 1 (16 hours)**:
   - Phase 1: Foundation (IP tracker, destination filter)
   - Phase 2: HTTP/1.1 forwarding with hyper

2. **Week 2 (16 hours)**:
   - Phase 3: Security hardening
   - Phase 4: Monitoring & detection
   - Phase 5: Testing & integration
   - Phase 6: Documentation

### 4.3 Deployment Strategy

1. **Development**: Feature branch + PR review
2. **Staging**: Deploy to staging with allowlist mode
3. **Canary**: 1% of production traffic for 24 hours
4. **Gradual Rollout**: 10% → 50% → 100% over 1 week
5. **Monitoring**: Watch metrics, respond to alerts

---

## 5. Questions for Engineering Team

1. **Security Mode**: Use "strict" mode with allowlist in production? Or start with "block_private"?
2. **Allowlist Domains**: Which domains should be in the initial allowlist?
3. **Body Limits**: Is 100MB reasonable? Or need higher for specific use cases?
4. **Monitoring Webhook**: Where should security alerts be sent?
5. **Token Revocation**: Auto-revoke on anomaly detection, or manual review first?
6. **HTTP/2 Phase 2**: Priority for pseudo-header mapping? Timeline?
7. **Performance SLO**: Are proposed targets (10ms p50, 500 req/s) acceptable?

---

**Document Status**: Ready for engineering review
**Next Action**: Team discussion + approval to proceed
**Estimated Start Date**: Upon approval
**Estimated Completion**: 4 weeks from start
