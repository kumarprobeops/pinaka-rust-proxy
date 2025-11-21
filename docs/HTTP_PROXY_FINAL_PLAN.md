# HTTP Proxy Implementation Plan - Final Version

**Date**: 2025-11-21
**Timeline**: 42 hours (updated to include streaming body size check)
**Architecture**: Minimal - Direct TcpStream + httparse (NO Hyper client, NO reqwest)

---

## Overview

Add HTTP forwarding (GET, POST, etc.) to support Chrome connectivity probes while maintaining security.

**Current**: Returns 204 stub for non-CONNECT requests
**Target**: Forward HTTP/HTTPS requests with SSRF protection

---

## Architecture

### Server-Side (No Change)
- HTTP/2: Direct h2 crate ✅
- HTTP/1.1: Hyper server ✅

### Client-Side (NEW)
- Direct `TcpStream::connect(vetted_ip)`
- `httparse` for response parsing
- `tokio-rustls` for HTTPS
- Manual HTTP/1.1 request formatting

**Key principle: Connect to vetted IPs only, never re-resolve hostnames**

---

## Core Components

### 1. HTTP Client (http_client.rs) - NEW
```rust
pub async fn forward_request(
    vetted_ips: Vec<IpAddr>,
    port: u16,
    scheme: &str,
    method: &str,
    path: &str,
    host: &str,
    headers: HeaderMap,
    body: Option<Bytes>,
    config: &Config,
) -> Result<(StatusCode, HeaderMap, Bytes)> {

    // Shuffle vetted IPs for load distribution
    let mut ips = vetted_ips.clone();
    ips.shuffle(&mut thread_rng());

    let mut last_error = None;

    // Try each vetted IP until one succeeds
    for (idx, ip) in ips.iter().enumerate() {
        match try_single_ip(*ip, port, scheme, method, path, host,
                           &headers, body.as_ref(), config).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                warn!("IP {}/{} failed ({}): {}", idx+1, ips.len(), ip, e);
                last_error = Some(e);
                continue;
            }
        }
    }

    // All IPs failed
    Err(last_error.unwrap())
}

async fn try_single_ip(
    ip: IpAddr,
    port: u16,
    scheme: &str,
    // ... other params
) -> Result<(StatusCode, HeaderMap, Bytes)> {

    // 1. Connect with timeout
    let stream = timeout(
        Duration::from_secs(config.connect_timeout),
        TcpStream::connect((ip, port))
    ).await??;

    // 2. TLS handshake if HTTPS
    let mut stream: Box<dyn AsyncRead + AsyncWrite + Unpin> = if scheme == "https" {
        let tls_config = build_tls_config()?; // webpki-roots, no-verify for testing
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(host)?;
        let tls = connector.connect(server_name, stream).await?;
        Box::new(tls)
    } else {
        Box::new(stream)
    };

    // 3. Write HTTP request
    let req_bytes = format_http_request(method, path, host, &headers, body)?;
    timeout(
        Duration::from_secs(config.write_timeout),
        stream.write_all(&req_bytes)
    ).await??;

    // 4. Read response with size limit
    let (status, resp_headers, body) = read_http_response(
        &mut stream,
        config.max_response_body_size,
        config.read_timeout
    ).await?;

    Ok((status, resp_headers, body))
}

fn format_http_request(
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> Result<Bytes> {
    let mut buf = BytesMut::new();

    // Request line (origin-form, not absolute-form)
    buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());

    // Host header (required)
    buf.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());

    // Filtered headers (no hop-by-hop)
    for (name, value) in headers {
        if !is_hop_by_hop(name) {
            buf.extend_from_slice(format!("{}: {}\r\n", name, value.to_str()?).as_bytes());
        }
    }

    // Content-Length if body present
    if let Some(body) = body {
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }

    buf.extend_from_slice(b"\r\n");

    // Body
    if let Some(body) = body {
        buf.extend_from_slice(body);
    }

    Ok(buf.freeze())
}

async fn read_http_response(
    stream: &mut (dyn AsyncRead + AsyncWrite + Unpin),
    max_body_size: usize,
    read_timeout: u64,
) -> Result<(StatusCode, HeaderMap, Bytes)> {

    // Read headers
    let mut header_buf = vec![0u8; 8192];
    let n = timeout(
        Duration::from_secs(read_timeout),
        stream.read(&mut header_buf)
    ).await??;

    // Parse with httparse
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let status = match response.parse(&header_buf[..n])? {
        httparse::Status::Complete(headers_len) => {
            let status = StatusCode::from_u16(response.code.unwrap())?;

            // Read body based on Content-Length or chunked
            let body = read_body(
                stream,
                &response.headers,
                &header_buf[headers_len..n],
                max_body_size,
                read_timeout
            ).await?;

            // Check body size limit
            if body.len() > max_body_size {
                return Err(HttpClientError::ResponseTooLarge {
                    size: body.len(),
                    limit: max_body_size,
                });
            }

            (status, convert_headers(response.headers), body)
        }
        _ => return Err(HttpClientError::IncompleteResponse),
    };

    Ok(status)
}

fn build_tls_config() -> Result<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(webpki_roots::TLS_SERVER_ROOTS.clone())
        .with_no_client_auth();

    // Enforce HTTP/1.1 (no HTTP/2)
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // For testing: disable verification if env var set
    if std::env::var("DISABLE_TLS_VERIFY").is_ok() {
        config.dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Ok(config)
}
```

**New dependencies:**
```toml
httparse = "1.8"
webpki-roots = "0.26"
rand = "0.8"  # For IP shuffle

# Note: reqwest remains for backend API communication and alert webhooks only
# NOT used for upstream HTTP forwarding (we use manual TcpStream + httparse)
```

---

### 2. Destination Filter (destination_filter.rs) - ENHANCED

```rust
pub struct DestinationFilter {
    resolver: Arc<TokioAsyncResolver>,
    dns_cache: Arc<Mutex<LruCache<String, CachedResolution>>>,
    blocked_ranges: Vec<IpNetwork>,
    blocked_hostnames: HashSet<String>,
    resolver_timeout: Duration,
}

struct CachedResolution {
    ips: Vec<IpAddr>,
    resolved_at: Instant,
}

impl DestinationFilter {
    pub fn new(config: &Config) -> Self {
        let cache_size = config.dns_cache_size.unwrap_or(5000);

        Self {
            resolver: Arc::new(build_resolver(config.resolver_timeout)),
            dns_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap()
            ))),
            blocked_ranges: load_blocked_ranges(),
            blocked_hostnames: load_blocked_hostnames(),
            resolver_timeout: Duration::from_secs(config.resolver_timeout.unwrap_or(5)),
        }
    }

    /// Returns ALL vetted IPs - caller must try them in order
    pub async fn check_and_resolve(&self, host: &str) -> Result<Vec<IpAddr>> {

        // 1. Check hostname blocklist
        if self.is_hostname_blocked(host) {
            return Err(DestinationError::BlockedHostname(host.to_string()));
        }

        // 2. Resolve with cache
        let ips = self.resolve_with_cache(host).await?;

        // 3. Check ALL IPs against blocklist
        for ip in &ips {
            if self.is_ip_blocked(*ip) {
                return Err(DestinationError::BlockedIpRange(*ip));
            }
        }

        Ok(ips)
    }

    async fn resolve_with_cache(&self, host: &str) -> Result<Vec<IpAddr>> {
        let mut cache = self.dns_cache.lock().await;

        // Check cache (60s TTL)
        if let Some(cached) = cache.get(host) {
            if cached.resolved_at.elapsed() < Duration::from_secs(60) {
                return Ok(cached.ips.clone());
            }
        }

        // Resolve with timeout
        let lookup = timeout(
            self.resolver_timeout,
            self.resolver.lookup_ip(host)
        ).await??;

        let ips: Vec<IpAddr> = lookup.iter().collect();

        // Cache result
        cache.put(host.to_string(), CachedResolution {
            ips: ips.clone(),
            resolved_at: Instant::now(),
        });

        Ok(ips)
    }

    fn is_hostname_blocked(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();

        // Exact match
        if self.blocked_hostnames.contains(&host_lower) {
            return true;
        }

        // localhost variants
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "ip6-localhost"
            || host_lower == "ip6-loopback" {
            return true;
        }

        false
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        for range in &self.blocked_ranges {
            if range.contains(ip) {
                return true;
            }
        }
        false
    }
}

fn load_blocked_hostnames() -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert("localhost".to_string());
    set.insert("metadata.google.internal".to_string());
    set.insert("metadata.azure.com".to_string());
    set.insert("instance-data.ec2.internal".to_string());
    set
}

const BLOCKED_IP_RANGES: &[&str] = &[
    // IPv4 Private
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "169.254.169.254/32",

    // IPv6 Private
    "::1/128",
    "fe80::/10",
    "fc00::/7",
    "fd00:ec2::254/128",
];
```

**Config:**
```bash
DNS_CACHE_SIZE=5000                # Default: 5000 hostnames
DNS_CACHE_TTL=60                   # Default: 60 seconds
DNS_RESOLVER_TIMEOUT=5             # Default: 5 seconds
```

---

### 3. IP Tracker (ip_tracker.rs) - FIXED

```rust
pub struct IpTracker {
    cache: Arc<Mutex<LruCache<String, TokenIpState>>>,
    max_ips_per_token: usize,
    entry_ttl: Duration,
}

impl IpTracker {
    pub fn new(config: &Config) -> Self {
        let cache_size = config.ip_tracker_cache_size.unwrap_or(10_000);

        Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(cache_size).unwrap()
            ))),
            max_ips_per_token: config.max_ips_per_token.unwrap_or(5),
            entry_ttl: Duration::from_secs(config.ip_tracker_ttl.unwrap_or(3600)),
        }
    }

    pub async fn check_and_track(&self, token_id: &str, client_ip: IpAddr)
        -> Result<(), IpTrackerError> {

        let normalized_ip = normalize_dual_stack_ip(client_ip);
        let mut cache = self.cache.lock().await;

        let state = match cache.get_mut(token_id) {
            Some(state) => {
                // Check TTL
                if state.created_at.elapsed() > self.entry_ttl {
                    state.ips.clear();
                    state.created_at = Instant::now();
                }
                state
            }
            None => {
                cache.put(token_id.to_string(), TokenIpState {
                    ips: BTreeSet::new(),
                    created_at: Instant::now(),
                });
                cache.get_mut(token_id).unwrap()
            }
        };

        // Already tracked?
        if state.ips.contains(&normalized_ip) {
            return Ok(());
        }

        // Check limit
        if state.ips.len() >= self.max_ips_per_token {
            return Err(IpTrackerError::LimitExceeded {
                token_id: token_id.to_string(),
                current_count: state.ips.len(),
                limit: self.max_ips_per_token,
            });
        }

        state.ips.insert(normalized_ip);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpTrackerError {
    #[error("IP limit exceeded: {current_count}/{limit} unique IPs used. Please refresh your token.")]
    LimitExceeded {
        token_id: String,
        current_count: usize,
        limit: usize,
    },
}
```

**Config:**
```bash
MAX_IPS_PER_TOKEN=5
IP_TRACKER_CACHE_SIZE=10000
IP_TRACKER_TTL_SECONDS=3600
```

---

### 4. Body Limiter - CLARIFIED

**Request body over-limit**: Return 413 to client before forwarding
**Response body over-limit**: Return 502 Bad Gateway to client

```rust
// In server.rs
async fn handle_http_forward(req: Request<Incoming>, config: Arc<Config>)
    -> Result<Response<Full<Bytes>>, hyper::Error> {

    // Check request body size
    if let Some(content_length) = req.headers().get("content-length") {
        let size: usize = content_length.to_str()?.parse()?;
        if size > config.max_request_body_size {
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("Connection", "close")
                .body(Full::new(Bytes::from(
                    format!("Request body too large: {} bytes (limit: {})",
                           size, config.max_request_body_size)
                )))
                .unwrap());
        }
    }

    // ... forward request ...

    match forward_result {
        Err(HttpClientError::ResponseTooLarge { size, limit }) => {
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Connection", "close")
                .body(Full::new(Bytes::from(
                    format!("Upstream response too large: {} bytes (limit: {})",
                           size, limit)
                )))
                .unwrap())
        }
        // ... other error handling
    }
}
```

**Config:**
```bash
MAX_REQUEST_BODY_SIZE=104857600    # 100MB
MAX_RESPONSE_BODY_SIZE=104857600   # 100MB
```

---

### 5. Monitoring & Metrics - DEFINED

```rust
// src/metrics.rs - NEW

use prometheus::{Counter, Histogram, IntGauge};

pub struct ProxyMetrics {
    pub http_requests_total: Counter,
    pub http_request_duration: Histogram,
    pub http_blocked_destinations: Counter,
    pub http_ip_limit_violations: Counter,
    pub http_body_size_errors: Counter,
    pub active_tokens: IntGauge,
}

impl ProxyMetrics {
    pub fn new() -> Self {
        Self {
            http_requests_total: register_counter!(
                "http_proxy_requests_total",
                "Total HTTP forwarding requests"
            ).unwrap(),
            // ... other metrics
        }
    }
}

// Export metrics endpoint
pub async fn metrics_handler() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode_to_string(&metric_families).unwrap()
}
```

**Alerting via webhook:**
```rust
// src/security/alerts.rs - NEW

pub async fn send_alert(alert: SecurityAlert, config: &Config) {
    if let Some(webhook_url) = &config.alert_webhook_url {
        let payload = serde_json::json!({
            "alert_type": alert.alert_type(),
            "severity": alert.severity(),
            "message": alert.message(),
            "timestamp": Utc::now(),
        });

        let _ = reqwest::Client::new()
            .post(webhook_url)
            .json(&payload)
            .timeout(Duration::from_secs(5))
            .send()
            .await;
    }
}
```

**Config:**
```bash
METRICS_ENABLED=true
METRICS_PORT=9090
ALERT_WEBHOOK_URL=https://alerts.probeops.com/webhook
```

---

## Implementation Phases

### Phase 1: Foundation (8h)
- [ ] destination_filter.rs (DNS cache, hostname blocklist, timeout)
- [ ] ip_tracker.rs (LRU capacity, user-facing error)
- [ ] config.rs (all new config fields)
- [ ] Unit tests: 15 tests

### Phase 2: HTTP Client (12h)
- [ ] http_client.rs (TcpStream, httparse, TLS)
- [ ] IP retry logic (shuffle, try all)
- [ ] Request formatting (origin-form)
- [ ] Response parsing (Content-Length, chunked)
- [ ] Unit tests: 20 tests

### Phase 3: Integration (8h)
- [ ] Wire http_client into server.rs
- [ ] Body size limit enforcement (413 request, 502 response)
- [ ] Error mapping (TLS, timeout, size)
- [ ] Integration tests: 15 tests (local nginx)

### Phase 4: Security & Monitoring (8h)
- [ ] Streaming body size check (avoid buffering full request body)
  - Implement streaming body reader with size counter
  - Return 413 as soon as size limit exceeded (before full body read)
  - Add body size metrics for monitoring
- [ ] metrics.rs (Prometheus export)
  - IP retry count, failure reasons, body size distribution
  - DNS cache hit/miss rates
  - TLS handshake latency
- [ ] alerts.rs (webhook delivery)
- [ ] Security tests: 10 tests (SSRF, blocklists)

### Phase 5: Testing & Documentation (6h)
- [ ] Load tests: 3 scenarios (h2load, concurrent, large bodies)
- [ ] HTTPS end-to-end tests: 5 tests
- [ ] Documentation: operations guide

**Total: 42 hours** (Phase 1: 8h, Phase 2: 12h, Phase 3: 8h, Phase 4: 8h, Phase 5: 6h)

---

## Must-Have Tests (55 total)

### Unit Tests (35)
- Destination filter: 12 (DNS cache, blocklists, timeout)
- IP tracker: 8 (LRU, TTL, dual-stack)
- HTTP client: 15 (request format, response parse, TLS, retry)

### Integration Tests (15)
- Basic HTTP GET/POST: 3
- HTTPS with TLS: 3
- Body size limits (413, 502): 3
- IP limit enforcement: 2
- Destination blocking: 2
- Retry logic (multi-IP): 2

### Security Tests (5)
- SSRF (RFC1918, metadata): 3
- Hostname blocklist: 2

---

## Configuration Summary

```bash
# HTTP Forwarding
HTTP_PROXY_ENABLED=true
MAX_REQUEST_BODY_SIZE=104857600
MAX_RESPONSE_BODY_SIZE=104857600
CONNECT_TIMEOUT_SECONDS=10
READ_TIMEOUT_SECONDS=30
WRITE_TIMEOUT_SECONDS=30

# DNS
DNS_CACHE_SIZE=5000
DNS_CACHE_TTL=60
DNS_RESOLVER_TIMEOUT=5

# IP Tracking
MAX_IPS_PER_TOKEN=5
IP_TRACKER_CACHE_SIZE=10000
IP_TRACKER_TTL_SECONDS=3600

# TLS
DISABLE_TLS_VERIFY=false  # Only for testing

# Monitoring
METRICS_ENABLED=true
METRICS_PORT=9090
ALERT_WEBHOOK_URL=https://alerts.probeops.com/webhook
```

---

## Success Criteria

- ✅ Chrome opens 10+ tabs without 405 errors
- ✅ Both HTTP and HTTPS requests work
- ✅ SSRF protection blocks RFC1918/metadata
- ✅ IP retry succeeds when first IP fails
- ✅ Body size limits enforced (413 request, 502 response)
- ✅ All 55 must-have tests pass
- ✅ Prometheus metrics exported

---

## Dependencies

```toml
[dependencies]
# Existing (no change)
h2 = "0.4"
hyper = { version = "1.0", features = ["server"] }
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"

# NEW for HTTP forwarding
httparse = "1.8"
webpki-roots = "0.26"
rand = "0.8"

# NEW for monitoring
prometheus = "0.13"

# DNS & SSRF
trust-dns-resolver = "0.23"
ipnetwork = "0.20"
lru = "0.12"
```

**Total: ~350 KB added dependencies**

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| DNS rebinding | Single lookup, connect to vetted IPs only |
| SSRF | Hostname + IP blocklists before connect |
| Token leak | IP limits, metrics, alerting |
| DoS (large bodies) | Size limits, 413/502 errors |
| Connection failures | Retry all vetted IPs before failing |
| TLS cert issues | webpki-roots, disable-verify for testing |

---

**Ready to implement: Approval needed to start Phase 1**
