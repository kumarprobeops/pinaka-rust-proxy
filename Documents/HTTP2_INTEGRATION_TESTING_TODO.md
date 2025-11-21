# HTTP/2 Integration Testing - Future Work

## Current Gap

The Phase 4 HTTP/2 Extended CONNECT handler is implemented and functional, but lacks automated integration test coverage. The HTTP/2 code path (`serve_h2`, `handle_h2_connect`, `tunnel_h2_streams`) has not been exercised by tests.

## What's Tested

✅ Authority parsing (shared by HTTP/1.1 and HTTP/2)
✅ Error handler logic (shared by HTTP/1.1 and HTTP/2)
✅ JWT authentication module
✅ Rate limiting module
✅ HTTP/1.1 CONNECT flow end-to-end

## What's Not Tested

❌ HTTP/2 handshake (ALPN negotiation, h2 server connection)
❌ HTTP/2 CONNECT method validation
❌ Proxy-Authorization header over HTTP/2 streams
❌ JWT auth error responses over HTTP/2 (407, 400, 403)
❌ Rate limiting over HTTP/2 (429, 503)
❌ Bidirectional tunnel flow over HTTP/2 streams
❌ Flow control behavior under backpressure

## Recommended Approach

### Option 1: In-Process Integration Tests (Preferred)

Create tests in `tests/http2_integration.rs` (separate from unit tests):

```rust
use h2::{client, server};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_h2_connect_missing_auth() {
    // 1. Start TCP listener on localhost
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 2. Spawn server task
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut h2 = server::handshake(stream).await.unwrap();

        while let Some(result) = h2.accept().await {
            let (request, respond) = result.unwrap();
            // Call actual handler
            handle_h2_connect(request, respond, config).await;
        }
    });

    // 3. Client connects
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut client, h2) = client::handshake(stream).await.unwrap();

    tokio::spawn(async move { h2.await });

    // 4. Send CONNECT without auth
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(())
        .unwrap();

    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    // 5. Assert 407 with Bearer challenge
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    assert!(response.headers().get("proxy-authenticate").is_some());
}
```

**Key Requirements:**
- Use `tokio::spawn` for server task to avoid blocking
- Properly close connections with `drop(client)` and awaiting h2 connection
- Add timeout wrappers to prevent hanging tests
- Test all error paths: 407, 400, 403, 429, 503
- Test successful CONNECT with tunnel data transfer

### Option 2: External Client Testing

Use `curl` or similar HTTP/2 client against a running test server:

```rust
#[tokio::test]
async fn test_h2_via_external_client() {
    // Start server on test port
    let server = TestServer::start("127.0.0.1:8443").await;

    // Use curl HTTP/2
    let output = Command::new("curl")
        .args(["--http2", "-x", "https://127.0.0.1:8443", "https://example.com"])
        .output()
        .await
        .unwrap();

    assert_eq!(output.status.code(), Some(0));

    server.shutdown().await;
}
```

**Pros:** Realistic client behavior
**Cons:** Requires external dependencies, harder to debug

### Option 3: Tower-Test Framework

Use `tower-test` for mocking h2 connections:

```rust
use tower_test::mock;

#[tokio::test]
async fn test_h2_handler_with_tower() {
    let (mut service, mut handle) = mock::pair();

    // Mock h2 stream
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(RecvStream::mock())
        .unwrap();

    let response_future = service.call(request);

    // Assert response
    let response = response_future.await.unwrap();
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
}
```

**Pros:** Clean API, good for service-layer testing
**Cons:** Requires additional dependencies, learning curve

## Implementation Checklist

When implementing HTTP/2 integration tests, cover these scenarios:

### Authentication Tests
- [ ] Missing Proxy-Authorization header → 407 with Bearer challenge
- [ ] Malformed Proxy-Authorization (no "Bearer ") → 400
- [ ] Invalid JWT signature → 403
- [ ] Expired JWT → 407
- [ ] Valid JWT but wrong region → 403

### Rate Limiting Tests
- [ ] Exceed request rate limit → 429
- [ ] Exceed max active tokens → 503

### Authority Validation Tests
- [ ] Missing port in authority → 400
- [ ] Port 0 → 400
- [ ] Port > 65535 → 400
- [ ] Empty host → 400

### Successful CONNECT Tests
- [ ] Valid auth + valid authority → 200 OK
- [ ] Bidirectional data transfer through tunnel
- [ ] Upstream connection failure → 502

### Flow Control Tests
- [ ] Large data transfer triggers backpressure
- [ ] send_with_flow_control polls for capacity
- [ ] WINDOW_UPDATE frames handled correctly

## Files to Modify

1. **Create:** `tests/http2_integration.rs` - New integration test file
2. **Update:** `Cargo.toml` - Add test dependencies if using tower-test
3. **Document:** Update this file with implementation status

## Success Criteria

- [ ] All HTTP/2 error paths tested (407, 400, 403, 429, 502, 503)
- [ ] Successful CONNECT with data transfer validated
- [ ] Flow control behavior verified
- [ ] Tests run reliably without timeouts
- [ ] CI/CD pipeline includes HTTP/2 tests

## Timeline

**Estimated Effort:** 4-6 hours
- 2 hours: Set up test infrastructure (TCP loopback, h2 client/server)
- 2 hours: Implement 10-15 test cases
- 1 hour: Debug connection lifecycle issues
- 1 hour: Document and integrate with CI/CD

**Priority:** Medium (handler is functional, but untested code path is risk)

## Notes

- Current handler code is production-ready (implements RFC 8441, flow control, auth, rate limiting)
- No changes to handler code needed, only test additions
- Tests would validate behavior, not drive implementation
- Consider adding these tests before first production deployment using HTTP/2
