# Pinaka Rust Proxy - Operations Guide

## Table of Contents
1. [Deployment](#deployment)
2. [Configuration](#configuration)
3. [Monitoring](#monitoring)
4. [Testing](#testing)
5. [Troubleshooting](#troubleshooting)
6. [Security](#security)
7. [Performance Tuning](#performance-tuning)

---

## Deployment

### Prerequisites
- Rust 1.70+ (stable toolchain)
- TLS certificates (self-signed for dev, Let's Encrypt for production)
- JWT secret key (minimum 32 characters)
- Linux server (tested on Ubuntu 20.04/22.04)

### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd pinaka-rust-proxy

# Build release binary
cargo build --release

# Binary location
./target/release/probe-proxy
```

### Docker Deployment

```bash
# Build Docker image
docker build -t pinaka-rust-proxy:latest .

# Run container
docker run -d \
  --name probe-proxy \
  -p 8443:8443 \
  -p 9090:9090 \
  -e TLS_CERT_PATH=/certs/cert.pem \
  -e TLS_KEY_PATH=/certs/key.pem \
  -e PROXY_PORT=8443 \
  -e JWT_SECRET="your_secret_at_least_32_characters" \
  -e HTTP_PROXY_ENABLED=true \
  -v /path/to/certs:/certs:ro \
  pinaka-rust-proxy:latest
```

### Systemd Service

Create `/etc/systemd/system/probe-proxy.service`:

```ini
[Unit]
Description=Pinaka Rust Proxy Server
After=network.target

[Service]
Type=simple
User=probeops
Group=probeops
WorkingDirectory=/opt/probe-proxy
Environment="TLS_CERT_PATH=/etc/probe-proxy/cert.pem"
Environment="TLS_KEY_PATH=/etc/probe-proxy/key.pem"
Environment="PROXY_PORT=8443"
Environment="JWT_SECRET=<your-secret-key>"
Environment="HTTP_PROXY_ENABLED=true"
ExecStart=/opt/probe-proxy/probe-proxy
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable probe-proxy
sudo systemctl start probe-proxy
sudo systemctl status probe-proxy
```

---

## Configuration

### Environment Variables

#### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `TLS_CERT_PATH` | Path to TLS certificate | `/etc/certs/cert.pem` |
| `TLS_KEY_PATH` | Path to TLS private key | `/etc/certs/key.pem` |
| `PROXY_PORT` | Proxy listening port | `8443` |
| `JWT_SECRET` | JWT signing secret (32+ chars) | `your_secret_key_minimum_32_chars` |

#### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTP_PROXY_ENABLED` | Enable HTTP forwarding | `false` |
| `RATE_LIMIT_PER_MINUTE` | Requests per minute per token | `10000` |
| `RATE_LIMIT_BURST` | Burst capacity | `500` |
| `MAX_IPS_PER_TOKEN` | Max unique IPs per token | `5` |
| `CONNECT_TIMEOUT_SECS` | Connection timeout | `10` |
| `READ_TIMEOUT_SECS` | Read operation timeout | `30` |
| `WRITE_TIMEOUT_SECS` | Write operation timeout | `30` |
| `DNS_CACHE_SIZE` | DNS cache entries | `100` |
| `DNS_CACHE_TTL_SECS` | DNS cache TTL | `60` |
| `MAX_DNS_RETRIES` | DNS resolution retries | `5` |
| `METRICS_PORT` | Prometheus metrics port | `9090` |
| `MAX_REQUEST_BODY_SIZE` | Max request body (bytes) | `10485760` (10 MB) |
| `MAX_RESPONSE_BODY_SIZE` | Max response body (bytes) | `52428800` (50 MB) |
| `DISABLE_TLS_VERIFY_NONPROD` | Disable TLS verification (dev only) | unset |
| `ENVIRONMENT` | Environment name | `production` |

#### Security Notes

- **JWT_SECRET**: Generate with `openssl rand -base64 32`
- **DISABLE_TLS_VERIFY_NONPROD**: Never set in production! Server will panic if `ENVIRONMENT` contains "prod"
- **TLS Certificates**: Use Let's Encrypt for production, self-signed only for dev/test

### Configuration Validation

On startup, the proxy validates:
- TLS certificates exist and are readable
- JWT secret meets minimum length requirement
- Port is available and within valid range
- Environment-specific security settings (TLS verification)

---

## Monitoring

### Prometheus Metrics

The proxy exposes metrics on port 9090 (configurable via `METRICS_PORT`):

```bash
curl http://localhost:9090/metrics
```

#### Key Metrics

**Connection Metrics:**
- `proxy_connections_total` - Total connections handled
- `proxy_active_connections` - Currently active connections
- `proxy_connection_duration_seconds` - Connection duration histogram

**Request Metrics:**
- `proxy_requests_total{method, status}` - Total requests by method and status
- `proxy_request_duration_seconds` - Request latency histogram
- `proxy_request_body_bytes` - Request body size histogram
- `proxy_response_body_bytes` - Response body size histogram

**Error Metrics:**
- `proxy_errors_total{error_type}` - Errors by type (auth, ssrf, timeout, etc.)

**Security Metrics:**
- `proxy_ssrf_blocked_total{reason}` - SSRF attempts blocked
- `proxy_rate_limit_exceeded_total` - Rate limit violations
- `proxy_ip_limit_exceeded_total` - IP limit violations

**Performance Metrics:**
- `proxy_dns_cache_hits_total` - DNS cache hit rate
- `proxy_dns_cache_misses_total` - DNS cache miss rate
- `proxy_dns_resolution_duration_seconds` - DNS resolution time

### Health Checks

```bash
# Check if proxy is listening
netstat -tlnp | grep :8443

# Check TLS handshake
echo | openssl s_client -connect localhost:8443 -brief

# Test authentication endpoint
printf "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n" | \
  openssl s_client -connect localhost:8443 -quiet 2>&1 | grep "407"
```

### Log Monitoring

```bash
# Follow logs (systemd)
sudo journalctl -u probe-proxy -f

# Search for errors
sudo journalctl -u probe-proxy | grep -i error

# View startup logs
sudo journalctl -u probe-proxy --since "10 minutes ago"
```

### Alerting Rules

Recommended Prometheus alerts:

```yaml
groups:
  - name: proxy_alerts
    rules:
      - alert: HighErrorRate
        expr: rate(proxy_errors_total[5m]) > 0.1
        for: 5m
        annotations:
          summary: "High proxy error rate"

      - alert: HighMemoryUsage
        expr: process_resident_memory_bytes > 2e9
        for: 10m
        annotations:
          summary: "Proxy memory usage above 2GB"

      - alert: SSRFAttemptsSpike
        expr: rate(proxy_ssrf_blocked_total[5m]) > 1
        for: 2m
        annotations:
          summary: "SSRF attack attempts detected"
```

---

## Testing

### Integration Tests

Run the comprehensive integration test suite:

```bash
# Make script executable
chmod +x /tmp/test_http_proxy.sh

# Set proxy details
export PROXY_HOST=localhost
export PROXY_PORT=8443
export TOKEN="your-jwt-token"

# Run tests
/tmp/test_http_proxy.sh
```

The script tests:
1. HTTP GET requests
2. HTTP POST with JSON body
3. HTTPS CONNECT method
4. Authentication enforcement (407 errors)
5. SSRF protection (localhost, RFC1918, metadata endpoints)
6. Chunked transfer encoding
7. Custom header preservation
8. Large response streaming

### Load Tests

Run performance load tests:

```bash
# Make script executable
chmod +x /tmp/run_load_tests.sh

# Set configuration
export PROXY_HOST=localhost
export PROXY_PORT=8443
export TOKEN="your-jwt-token"

# Run load tests
/tmp/run_load_tests.sh
```

Load test scenarios:
1. **Basic Throughput**: 10,000 requests, 100 concurrent
2. **High Concurrency**: 500 concurrent connections, 30 seconds
3. **Large Bodies**: 10 MB responses, streaming test
4. **POST Load**: 100 POST requests with 1 KB JSON bodies
5. **Memory Pressure**: 20 concurrent 5 MB responses

### Security Tests

Run automated security test suite:

```bash
# Run all security tests
cargo test --test security_tests -- --nocapture

# Run specific test group
cargo test --test security_tests destination_filter_tests -- --nocapture
```

Test coverage:
- ✅ SSRF protection (localhost, RFC1918, link-local, metadata)
- ✅ IP limit enforcement (5 IPs per token)
- ✅ DNS cache functionality
- ✅ Request/response body size limits
- ✅ Rate limiting (10k req/min, 500 burst)

---

## Troubleshooting

### Common Issues

#### 1. Proxy Not Starting

**Symptom**: Service fails to start or crashes immediately

**Check**:
```bash
# View startup errors
sudo journalctl -u probe-proxy -n 50

# Verify TLS certificates
openssl x509 -in /etc/probe-proxy/cert.pem -text -noout
openssl rsa -in /etc/probe-proxy/key.pem -check

# Check port availability
sudo netstat -tlnp | grep 8443
```

**Common Causes**:
- TLS certificate files not found or unreadable
- JWT_SECRET too short (must be 32+ characters)
- Port already in use
- DISABLE_TLS_VERIFY_NONPROD set in production environment

#### 2. Authentication Failures (407)

**Symptom**: All requests return 407 Proxy Authentication Required

**Check**:
```bash
# Verify JWT token
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq

# Test token decoding
docker exec probe-proxy ./validate-token "$TOKEN"
```

**Common Causes**:
- Expired JWT token (check `exp` claim)
- Wrong JWT_SECRET on server
- Missing or malformed `Proxy-Authorization` header

#### 3. SSRF False Positives

**Symptom**: Legitimate requests blocked with 403

**Check Logs**:
```bash
sudo journalctl -u probe-proxy | grep "SSRF blocked"
```

**Common Causes**:
- Domain resolves to private IP range
- Using internal TLD (.local, .internal, .lan)
- DNS poisoning attempt

**Resolution**: Update blocklist or use public DNS resolver

#### 4. High Memory Usage

**Symptom**: Process memory grows over time

**Check**:
```bash
# Monitor memory
ps aux | grep probe-proxy
top -p $(pgrep probe-proxy)

# Check metrics
curl http://localhost:9090/metrics | grep process_resident_memory
```

**Common Causes**:
- Large response bodies not being streamed
- Connection leaks
- DNS cache too large

**Resolution**:
- Review `MAX_RESPONSE_BODY_SIZE` setting
- Check for connection timeout issues
- Adjust `DNS_CACHE_SIZE`

#### 5. Rate Limit False Positives

**Symptom**: Legitimate traffic getting 429 errors

**Check**:
```bash
# View rate limit metrics
curl http://localhost:9090/metrics | grep rate_limit_exceeded

# Check token usage
sudo journalctl -u probe-proxy | grep "rate_limit_exceeded"
```

**Resolution**: Increase `RATE_LIMIT_PER_MINUTE` or `RATE_LIMIT_BURST`

### Debug Mode

Enable detailed logging:

```bash
# Set log level
export RUST_LOG=debug

# Restart service
sudo systemctl restart probe-proxy

# View debug logs
sudo journalctl -u probe-proxy -f
```

### Connection Tracing

Trace a specific connection:

```bash
# Enable connection tracing
export RUST_LOG=pinaka_rust_proxy=trace

# Follow specific connection
sudo journalctl -u probe-proxy -f | grep "conn_id=12345"
```

---

## Security

### TLS Configuration

**Certificate Requirements**:
- Valid X.509 certificate
- RSA 2048-bit or higher, or ECDSA P-256+
- TLS 1.2 minimum (TLS 1.3 recommended)

**Generate Self-Signed Certificate (Dev/Test Only)**:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

**Let's Encrypt (Production)**:

```bash
sudo certbot certonly --standalone -d proxy.example.com
sudo ln -s /etc/letsencrypt/live/proxy.example.com/fullchain.pem /etc/probe-proxy/cert.pem
sudo ln -s /etc/letsencrypt/live/proxy.example.com/privkey.pem /etc/probe-proxy/key.pem
```

### JWT Token Management

**Token Generation** (Python example):

```python
import jwt
import time

payload = {
    "token_id": "unique-token-id",
    "user_id": 123,
    "allowed_regions": ["us-east", "eu-west"],
    "exp": int(time.time()) + 3600,  # 1 hour expiry
    "iat": int(time.time())
}

secret = "your_secret_at_least_32_characters"
token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

**Required Claims**:
- `token_id` (string) - Unique identifier
- `user_id` (integer) - User/tenant ID
- `allowed_regions` (array) - Geographic regions allowed
- `exp` (integer) - Expiration timestamp
- `iat` (integer) - Issued-at timestamp

### Firewall Configuration

```bash
# Allow proxy port
sudo ufw allow 8443/tcp comment "Probe Proxy"

# Restrict metrics port to internal network
sudo ufw allow from 10.0.0.0/8 to any port 9090 proto tcp comment "Prometheus"

# Enable firewall
sudo ufw enable
```

### Security Hardening

**1. Run as Non-Root User**:
```bash
sudo useradd -r -s /bin/false probeops
sudo chown -R probeops:probeops /opt/probe-proxy
```

**2. Restrict File Permissions**:
```bash
sudo chmod 600 /etc/probe-proxy/key.pem
sudo chmod 644 /etc/probe-proxy/cert.pem
```

**3. Enable SELinux/AppArmor** (if available)

**4. Limit File Descriptors**:
```ini
# In systemd service file
LimitNOFILE=65536
```

**5. Disable TLS Verification Override**:
```bash
# Never set DISABLE_TLS_VERIFY_NONPROD in production
# Server will panic if ENVIRONMENT=production
```

---

## Performance Tuning

### System Limits

**Increase Open Files Limit**:

```bash
# Temporary
ulimit -n 65536

# Permanent - add to /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536
```

**Kernel TCP Tuning** (`/etc/sysctl.conf`):

```ini
# Increase max connections
net.core.somaxconn = 4096

# TCP buffer sizes
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 262144

# TIME_WAIT recycling
net.ipv4.tcp_tw_reuse = 1
```

Apply changes:
```bash
sudo sysctl -p
```

### Proxy Configuration Tuning

**High Throughput**:
```bash
RATE_LIMIT_PER_MINUTE=50000
RATE_LIMIT_BURST=2000
DNS_CACHE_SIZE=1000
DNS_CACHE_TTL_SECS=300
```

**Low Latency**:
```bash
CONNECT_TIMEOUT_SECS=5
READ_TIMEOUT_SECS=15
WRITE_TIMEOUT_SECS=15
DNS_CACHE_SIZE=500
DNS_CACHE_TTL_SECS=60
```

**Memory Constrained**:
```bash
MAX_REQUEST_BODY_SIZE=1048576    # 1 MB
MAX_RESPONSE_BODY_SIZE=10485760  # 10 MB
DNS_CACHE_SIZE=50
RATE_LIMIT_BURST=100
```

### Benchmarking

**Connection Capacity Test**:
```bash
# Test maximum concurrent connections
ab -n 10000 -c 1000 -X localhost:8443 http://httpbin.org/get
```

**Throughput Test**:
```bash
# Measure requests per second
wrk -t 8 -c 400 -d 30s --latency \
  -H "Proxy-Authorization: Bearer $TOKEN" \
  http://httpbin.org/get
```

**Memory Profiling**:
```bash
# Monitor memory during load
watch -n 1 'ps aux | grep probe-proxy | grep -v grep'
```

### Resource Monitoring

**CPU Usage**:
```bash
# Real-time CPU usage
top -p $(pgrep probe-proxy)

# Average CPU over time
sar -u 1 60
```

**Network Bandwidth**:
```bash
# Monitor network I/O
iftop -i eth0 -f "port 8443"

# Measure throughput
nload eth0
```

**Disk I/O**:
```bash
# Monitor disk usage (for logs)
iostat -x 1
```

---

## Maintenance

### Log Rotation

Configure logrotate (`/etc/logrotate.d/probe-proxy`):

```
/var/log/probe-proxy/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    missingok
    postrotate
        systemctl reload probe-proxy > /dev/null 2>&1 || true
    endscript
}
```

### Certificate Renewal

**Automated Let's Encrypt Renewal**:

```bash
# Certbot auto-renewal (cron)
0 0,12 * * * certbot renew --quiet --deploy-hook "systemctl reload probe-proxy"
```

**Manual Certificate Update**:

```bash
# Update certificates
sudo cp new-cert.pem /etc/probe-proxy/cert.pem
sudo cp new-key.pem /etc/probe-proxy/key.pem

# Reload proxy (graceful)
sudo systemctl reload probe-proxy
```

### Backup

**Configuration Backup**:
```bash
tar czf probe-proxy-backup-$(date +%Y%m%d).tar.gz \
  /etc/probe-proxy/ \
  /etc/systemd/system/probe-proxy.service
```

### Updates

**Update Proxy Binary**:

```bash
# Pull latest code
git pull origin main

# Build new version
cargo build --release

# Stop service
sudo systemctl stop probe-proxy

# Replace binary
sudo cp target/release/probe-proxy /opt/probe-proxy/

# Start service
sudo systemctl start probe-proxy

# Verify
sudo systemctl status probe-proxy
```

---

## Support

### Documentation
- [Implementation Plan](HTTP_PROXY_IMPLEMENTATION_PLAN.md)
- [Security Architecture](SECURITY_ARCHITECTURE.md)
- [Architecture Diagram](HTTP_PROXY_ARCHITECTURE.md)

### Metrics Dashboard
- Prometheus: `http://localhost:9090/metrics`
- Grafana: Import dashboard from `grafana/proxy-dashboard.json`

### Logs
- Systemd: `sudo journalctl -u probe-proxy`
- Docker: `docker logs probe-proxy`

### Health Status
```bash
# Quick health check
curl -k https://localhost:8443/health
```
