# Hyper vs Direct h2 - Clarification

**Date**: 2025-11-21
**Context**: Engineering feedback response correction

---

## Current Architecture (CORRECT - No Change Needed)

### HTTP/2 CONNECT Tunnels
- ✅ **Direct h2 crate** (src/server.rs:51-100)
- ✅ Reason: Extended CONNECT support, full stream control
- ✅ Status: Working perfectly, DO NOT CHANGE

### HTTP/1.1 CONNECT Tunnels
- ✅ **Hyper** (src/server.rs:779-833)
- ✅ Reason: Simpler for HTTP/1.1, built-in upgrade support
- ✅ Status: Working perfectly, DO NOT CHANGE

---

## What Changed in Engineering Feedback Response

### ❌ INCORRECT Suggestion (My Error)
I suggested using Hyper for **HTTP/1.1 forwarding (non-CONNECT)** to upstream servers.

This was **wrong** because I conflated two different use cases:

1. **Server-side protocol handling** (CONNECT tunnel establishment) ← Already uses Hyper for HTTP/1.1
2. **Client-side upstream requests** (HTTP forwarding) ← NEW feature, different concern

---

## Correct Approach for HTTP Forwarding

### The Real Question
When forwarding **non-CONNECT HTTP requests** (GET, POST, etc.), what should we use for the **upstream client**?

**Current code** (src/server.rs:824-832):
```rust
// Non-CONNECT methods return 204 stub
info!("[HTTP] Non-CONNECT {} request for {} - returning 204 (stub)", method, uri);
Ok(Response::builder()
    .status(StatusCode::NO_CONTENT)
    .body(Full::new(Bytes::new()))
    .unwrap())
```

**We need to replace this stub with actual HTTP forwarding.**

### Option 1: Use Hyper Client (My Incorrect Suggestion)
```rust
// Use hyper::client::conn::http1 to connect to upstream
let stream = TcpStream::connect(addr).await?;
let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
let resp = sender.send_request(req).await?;
```

**Pros:**
- Same stack as server-side HTTP/1.1
- TLS support via tokio-rustls
- Mature, well-tested

**Cons:**
- Adds complexity (need to manage client connections)
- Need to handle connection pooling manually
- Another layer on top of h2/http

### Option 2: Direct TcpStream + Manual HTTP (Recommended)
```rust
// Connect to vetted IP directly
let stream = TcpStream::connect(vetted_ip).await?;

// For HTTPS, wrap in TLS
let stream = if scheme == "https" {
    let tls = tls_connector.connect(server_name, stream).await?;
    Either::Right(tls)
} else {
    Either::Left(stream)
};

// Write HTTP request manually
stream.write_all(format!(
    "{} {} HTTP/1.1\r\n\
     Host: {}\r\n\
     {}\
     \r\n",
    method, path, host, headers
).as_bytes()).await?;

// Read response manually (or use httparse crate)
```

**Pros:**
- ✅ **Minimal dependencies** (aligns with original h2 direct approach)
- ✅ **Full control** over DNS resolution (use vetted IPs)
- ✅ **No abstraction layers** to bypass for SSRF protection
- ✅ **Consistent with h2 philosophy** (direct protocol handling)

**Cons:**
- More code to write
- Need to handle HTTP parsing (use `httparse` crate)
- Need to handle chunked encoding manually

### Option 3: Use `reqwest` (Originally Suggested, Rejected)
**Already rejected by first engineering feedback** - too heavy, duplicate TLS stack.

---

## Recommended Solution: Hybrid Approach

### For Server-Side (Receiving Client Requests)
- **HTTP/2**: Direct h2 crate ✅ (no change)
- **HTTP/1.1**: Hyper ✅ (no change)

### For Client-Side (Forwarding to Upstream)

#### Approach A: Minimal with httparse (Recommended)
```rust
// src/http_client.rs - NEW FILE

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use httparse;

pub async fn forward_http_request(
    vetted_ip: IpAddr,
    port: u16,
    scheme: &str,
    method: &str,
    path: &str,
    host: &str,
    headers: &HeaderMap,
    body: Option<Bytes>,
    tls_connector: &TlsConnector,
) -> Result<(StatusCode, HeaderMap, Bytes), HttpClientError> {

    // 1. Connect to vetted IP
    let stream = TcpStream::connect((vetted_ip, port)).await?;

    // 2. TLS handshake if HTTPS
    let mut stream: Box<dyn AsyncRead + AsyncWrite + Unpin> = if scheme == "https" {
        let server_name = ServerName::try_from(host)?;
        let tls_stream = tls_connector.connect(server_name, stream).await?;
        Box::new(tls_stream)
    } else {
        Box::new(stream)
    };

    // 3. Build HTTP request
    let mut req_bytes = BytesMut::new();
    req_bytes.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, path).as_bytes());
    req_bytes.extend_from_slice(format!("Host: {}\r\n", host).as_bytes());

    // Add headers (filtered)
    for (name, value) in headers {
        if !is_hop_by_hop(name) {
            req_bytes.extend_from_slice(format!("{}: {}\r\n", name, value.to_str()?).as_bytes());
        }
    }

    // Content-Length if body present
    if let Some(ref body) = body {
        req_bytes.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }

    req_bytes.extend_from_slice(b"\r\n");

    // 4. Send request
    stream.write_all(&req_bytes).await?;
    if let Some(body) = body {
        stream.write_all(&body).await?;
    }

    // 5. Read response
    let mut response_buf = vec![0u8; 8192];
    let n = stream.read(&mut response_buf).await?;

    // 6. Parse response headers
    let mut headers_parsed = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers_parsed);
    let headers_len = response.parse(&response_buf[..n])?;

    let status = StatusCode::from_u16(response.code.unwrap())?;

    // 7. Read response body
    let body_start = headers_len;
    let mut body_bytes = BytesMut::from(&response_buf[body_start..n]);

    // Read remaining body (if Content-Length or chunked)
    // ... (handle chunked encoding, content-length)

    Ok((status, response_headers, body_bytes.freeze()))
}
```

**Dependencies:**
```toml
[dependencies]
httparse = "1.8"  # Lightweight HTTP parser
tokio = { version = "1", features = ["io-util", "net"] }
tokio-rustls = "0.26"
```

#### Approach B: Hyper Client (If We Accept the Trade-off)
```rust
use hyper::client::conn::http1;

pub async fn forward_http_request(...) -> Result<...> {
    let stream = TcpStream::connect((vetted_ip, port)).await?;

    let stream = if scheme == "https" {
        let tls = tls_connector.connect(server_name, stream).await?;
        TokioIo::new(tls)
    } else {
        TokioIo::new(stream)
    };

    let (mut sender, conn) = http1::handshake(stream).await?;
    tokio::spawn(async move { conn.await });

    // Build origin-form request
    let req = Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("host", host)
        // ... filtered headers
        .body(body)?;

    let resp = sender.send_request(req).await?;
    Ok(resp)
}
```

**Dependencies:**
```toml
[dependencies]
hyper = { version = "1.0", features = ["client"] }
hyper-util = { version = "0.1", features = ["client"] }
```

---

## My Recommendation: Approach A (Minimal httparse)

### Rationale
1. **Consistent with original design philosophy**
   - Direct h2 crate for HTTP/2 (no Hyper server abstraction)
   - Direct httparse for HTTP/1.1 client (no Hyper client abstraction)

2. **Minimal dependencies**
   - `httparse` is tiny (parse only, no protocol state machine)
   - No duplicate HTTP stack

3. **Full control over SSRF protection**
   - Connect to vetted IP directly
   - No hidden DNS resolution in abstraction layers

4. **Simpler**
   - ~200 lines of code for basic HTTP/1.1 client
   - No connection pooling complexity
   - No hyper client state management

### Trade-offs
- **More code to write** (vs. using Hyper client)
- **Need to handle chunked encoding** (use `httparse` or simple state machine)
- **Less battle-tested** (but simpler, easier to audit)

---

## Corrected Engineering Feedback Response

### What I Should Have Said

**For HTTP Forwarding (non-CONNECT), use one of:**

1. **Minimal approach** (recommended): Direct `TcpStream` + `httparse` + `tokio-rustls`
2. **Hyper client approach** (if team prefers): `hyper::client::conn::http1`

**Do NOT touch existing server-side code:**
- HTTP/2 CONNECT: Keep direct h2 ✅
- HTTP/1.1 CONNECT: Keep Hyper ✅

---

## Updated Dependencies (Minimal Approach)

```toml
[dependencies]
# Existing (no change)
h2 = "0.4"
hyper = { version = "1.0", features = ["server"] }  # Server only, not client
hyper-util = "0.1"
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"

# NEW for HTTP forwarding
httparse = "1.8"          # Lightweight HTTP parser (~100 KB)
webpki-roots = "0.26"     # CA certs for TLS verification

# Existing for SSRF protection
trust-dns-resolver = "0.23"
ipnetwork = "0.20"
lru = "0.12"
```

**No reqwest, no hyper client features.**

---

## Summary

**Original design decision was correct:**
- Use direct h2 for HTTP/2 (full control over Extended CONNECT)
- Use Hyper for HTTP/1.1 server (simpler than manual parsing)

**My engineering feedback response was misleading:**
- I suggested using Hyper client for upstream forwarding
- This is unnecessary complexity

**Correct approach:**
- Keep existing server-side code unchanged
- For new HTTP forwarding feature, use minimal approach:
  - Direct `TcpStream::connect(vetted_ip)`
  - `httparse` for response parsing
  - `tokio-rustls` for HTTPS
  - Manual HTTP/1.1 request formatting (~50 lines)

**Aligns with original philosophy: Direct protocol handling, minimal abstraction.**
