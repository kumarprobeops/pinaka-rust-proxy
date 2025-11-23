# Changelog

All notable changes to Pinaka Rust Proxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-23

### Added
- **Mixed Content Policy** - HTTP→HTTPS upgrade policy for enhanced security
  - Configurable policy modes: `allow`, `upgrade`, or `block` mixed content
  - Smart HTTPS probing before upgrade to avoid 404 errors
  - Configurable failure handling: `block`, `fallback`, or `warn`
  - Proper URI parsing using `url` crate (not naive string matching)
  - Expected coverage: 10-20% of mixed content (direct HTTP proxy requests)

- **New Environment Variables**:
  - `MIXED_CONTENT_POLICY` - Policy for handling HTTP requests with HTTPS Referer/Origin (default: `allow`)
  - `UPGRADE_FAILURE_ACTION` - Action to take when HTTPS upgrade fails (default: `warn`)
  - `UPGRADE_PROBE_TIMEOUT` - Timeout in milliseconds for HTTPS availability probe (default: `1000`)

- **Prometheus Metrics** - 6 new metrics for mixed content monitoring:
  - `http_proxy_mixed_content_detected_total` - Mixed content requests detected
  - `http_proxy_mixed_content_allowed_total` - Requests allowed through (by reason)
  - `http_proxy_mixed_content_blocked_total` - Requests blocked (403)
  - `http_proxy_mixed_content_upgraded_total` - Successful HTTP→HTTPS upgrades
  - `http_proxy_mixed_content_upgrade_failed_total` - Failed upgrade attempts (by failure reason)
  - `http_proxy_upgrade_probe_duration_seconds` - HTTPS probe latency distribution

### Technical Details
- **New Module**: `src/mixed_content.rs` - Core mixed content policy implementation
- **Integration**: Mixed content check runs after authentication, before SSRF protection
- **Dependencies**: Added `url = "2.5"` for proper URL parsing
- **CONNECT Tunnel Limitation**: Policy only applies to direct HTTP proxy requests (not resources fetched inside encrypted CONNECT tunnels)

### Use Cases
- Reduce browser "Not secure" warnings when HTTP resources are loaded from HTTPS pages
- Automatically upgrade HTTP→HTTPS where available (e.g., yahoo.com, ndtv.com mixed content)
- Configurable for different security postures (strict blocking, lenient fallback, or monitoring mode)

### Performance Impact
- HTTPS probe adds <100ms latency when policy is `upgrade` and mixed content is detected
- No impact when policy is `allow` (default)
- Minimal memory overhead (~1KB per probe)

### Deployment Notes
- Feature is **opt-in** - defaults to `allow` (no change to current behavior)
- Recommended configuration: `policy=upgrade`, `failure_action=warn`, `timeout=1000ms`
- See `MIXED_CONTENT_DEPLOYMENT.md` for deployment guide

## [0.1.0] - 2025-11-21

### Initial Release
- HTTP/2 Extended CONNECT (RFC 8441) with stream multiplexing
- HTTP/1.1 CONNECT fallback for compatibility
- Full HTTP forwarding (GET, POST, PUT, PATCH, DELETE)
- JWT authentication with HS256/HS384/HS512
- Token-based rate limiting (10,000 req/min, 500 burst)
- Request logging to backend API
- TLS 1.2/1.3 with certificate hot-reload
- Prometheus metrics instrumentation
- 97.9% RFC 9113 compliance
- Production deployment on ProbeOps probe nodes
