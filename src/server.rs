use anyhow::Result;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::{TcpStream};
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

use crate::auth::AuthError;
use crate::config::Config;
use crate::rate_limiter::RateLimitError;

/// Parse and validate CONNECT authority (host:port)
/// Returns (host, port) or error message
fn parse_authority(authority: &str) -> Result<(String, u16), String> {
    // Split by last colon to handle IPv6 addresses like [::1]:443
    let parts: Vec<&str> = authority.rsplitn(2, ':').collect();

    if parts.len() != 2 {
        return Err("Authority must be in host:port format".to_string());
    }

    let port_str = parts[0];
    let host = parts[1];

    // Validate host is not empty
    if host.is_empty() {
        return Err("Host cannot be empty".to_string());
    }

    // Parse and validate port
    let port: u16 = port_str.parse().map_err(|_| {
        format!("Invalid port '{}': must be a number between 1 and 65535", port_str)
    })?;

    // Validate port is in valid range (1-65535)
    if port == 0 {
        return Err("Invalid port: must be between 1 and 65535".to_string());
    }

    Ok((host.to_string(), port))
}

/// Serve HTTP/2 connections using direct h2 crate
pub async fn serve_h2(
    _tls_stream: TlsStream<TcpStream>,
    _config: Arc<Config>,
) -> Result<()> {
    info!("HTTP/2 connection handler started");

    // Phase 2: JWT authentication and rate limiting are available in config:
    // - config.jwt_validator.validate_request(&request) -> Result<JwtClaims, AuthError>
    // - config.rate_limiter.check_limit(&claims.token_id).await -> Result<(), RateLimitError>

    // TODO: Phase 4 - Implement HTTP/2 CONNECT handler
    // This will use the h2 crate directly to handle Extended CONNECT requests
    // See RUST_PROXY_IMPLEMENTATION_PLAN_V4_1_CONCRETE.md Phase 4 for implementation details
    //
    // Implementation will include:
    // 1. h2::server::handshake(tls_stream)
    // 2. Accept streams and validate CONNECT requests
    // 3. Authenticate: let claims = config.jwt_validator.validate_request(&request)?;
    // 4. Rate limit: config.rate_limiter.check_limit(&claims.token_id).await?;
    // 5. Connect to upstream and tunnel data

    // Placeholder: Just log and close for now
    info!("HTTP/2 handler not yet implemented - closing connection");

    Ok(())
}

/// Serve HTTP/1.1 connections using Hyper
pub async fn serve_http1(
    tls_stream: TlsStream<TcpStream>,
    config: Arc<Config>,
) -> Result<()> {
    info!("HTTP/1.1 connection handler started");

    // Wrap TLS stream in TokioIo for Hyper compatibility
    let io = TokioIo::new(tls_stream);

    // Create HTTP/1.1 connection
    let conn = hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let config = Arc::clone(&config);
                async move { handle_request(req, config).await }
            }),
        )
        .with_upgrades(); // Enable HTTP upgrades for CONNECT

    // Serve the connection
    if let Err(e) = conn.await {
        error!("HTTP/1.1 connection error: {}", e);
    }

    Ok(())
}

/// Handle individual HTTP/1.1 requests
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    debug!("Received {} request for {}", method, uri);

    // Only CONNECT method is supported for forward proxy
    if method != Method::CONNECT {
        warn!("Unsupported method: {}", method);
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Only CONNECT method is supported")))
            .unwrap());
    }

    // Handle CONNECT request
    handle_connect(req, config).await
}

/// Handle HTTP/1.1 CONNECT requests for TLS tunneling
/// Generic over body type to allow testing with Empty<Bytes>
async fn handle_connect<B>(
    mut req: Request<B>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync,
{
    let start_time = std::time::Instant::now();

    // Phase 3.0: Validate CONNECT target authority
    let target_host = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!("[CONNECT] Missing authority in CONNECT request");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "Bad Request: CONNECT requires a valid host:port authority"
                )))
                .unwrap());
        }
    };

    // Validate and parse host:port format
    let (_host, _port) = match parse_authority(&target_host) {
        Ok((h, p)) => (h, p),
        Err(err_msg) => {
            warn!("[CONNECT] Invalid authority {}: {}", target_host, err_msg);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(format!(
                    "Bad Request: {}", err_msg
                ))))
                .unwrap());
        }
    };

    // Note: target_host is used for TCP connection (already validated above)

    info!("[CONNECT] {} from client", target_host);

    // Phase 3.1: JWT Authentication
    let claims = match config.jwt_validator.validate_request(&req) {
        Ok(claims) => claims,
        Err(e) => {
            return handle_auth_error(e, &target_host, start_time);
        }
    };

    debug!("[CONNECT] Authenticated user_id={}, token_id={}, allowed_regions={:?}",
        claims.user_id, claims.token_id, claims.allowed_regions);

    // Note: Region validation is now handled in JwtValidator::validate()
    // which checks for wildcard "*" or specific region match

    // Phase 3.3: Rate Limiting
    match config.rate_limiter.check_limit(&claims.token_id).await {
        Ok(()) => {},
        Err(e) => {
            return handle_rate_limit_error(e, &target_host, &claims.token_id, start_time);
        }
    };

    debug!("[CONNECT] Rate limit check passed for token_id={}", claims.token_id);

    // Phase 3.4: Establish connection to target
    let upstream = match tokio::net::TcpStream::connect(&target_host).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[CONNECT] Failed to connect to {}: {}", target_host, e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to target")))
                .unwrap());
        }
    };

    info!("[CONNECT] Connected to upstream {}", target_host);

    // Phase 3.5: Spawn tunnel task and upgrade connection
    let target_host_for_log = target_host.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(upgraded, upstream, target_host.clone(), claims.user_id as i64, claims.token_id, start_time).await {
                    error!("[CONNECT] Tunnel error for {}: {}", target_host, e);
                }
            }
            Err(e) => {
                error!("[CONNECT] Upgrade error for {}: {}", target_host, e);
            }
        }
    });

    // Phase 3.6: Send 200 Connection Established
    info!("[CONNECT] Sending 200 Connection Established for {}", target_host_for_log);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// Bidirectional tunnel between client and upstream
async fn tunnel(
    upgraded: Upgraded,
    upstream: TcpStream,
    target_host: String,
    user_id: i64,
    token_id: String,
    start_time: std::time::Instant,
) -> Result<()> {
    let client = TokioIo::new(upgraded);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Bidirectional copy: client <-> upstream
    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    let (c_to_u, u_to_c) = tokio::try_join!(client_to_upstream, upstream_to_client)?;

    let duration = start_time.elapsed();
    let total_bytes = c_to_u + u_to_c;

    info!(
        "[CONNECT] Completed {} - user_id={}, token_id={}, duration={:?}, \
         client→upstream={} bytes, upstream→client={} bytes, total={} bytes",
        target_host, user_id, token_id, duration,
        c_to_u, u_to_c, total_bytes
    );

    Ok(())
}

/// Handle JWT authentication errors
fn handle_auth_error(
    error: AuthError,
    target_host: &str,
    start_time: std::time::Instant,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let duration = start_time.elapsed();

    let (status, message) = match error {
        AuthError::MissingHeader => {
            warn!("[CONNECT] Authentication failed for {}: missing header (duration={:?})",
                target_host, duration);
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "Proxy authentication required. Please provide a valid JWT token in the Proxy-Authorization or Authorization header."
            )
        },
        AuthError::InvalidFormat => {
            warn!("[CONNECT] Authentication failed for {}: invalid format (duration={:?})",
                target_host, duration);
            (
                StatusCode::BAD_REQUEST,
                "Invalid authentication format. Expected: Proxy-Authorization: Bearer <token>"
            )
        },
        AuthError::TokenExpired => {
            warn!("[CONNECT] Authentication failed for {}: token expired (duration={:?})",
                target_host, duration);
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "JWT token has expired. Please refresh your token or login again to the ProbeOps platform."
            )
        },
        AuthError::ValidationFailed(ref msg) => {
            warn!("[CONNECT] Authentication failed for {}: {} (duration={:?})",
                target_host, msg, duration);
            (
                StatusCode::FORBIDDEN,
                "Authentication failed: Invalid JWT token"
            )
        },
        AuthError::RegionNotAllowed(ref msg) => {
            warn!("[CONNECT] Authentication failed for {}: {} (duration={:?})",
                target_host, msg, duration);
            (
                StatusCode::FORBIDDEN,
                "Access denied: Region not in allowed list"
            )
        },
    };

    let mut response = Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(message)))
        .unwrap();

    // Add Proxy-Authenticate header for 407 responses (required for proper proxy auth)
    // Use Bearer scheme to match JWT authentication (RFC 7235)
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            "Proxy-Authenticate",
            "Bearer realm=\"ProbeOps Forward Proxy\"".parse().unwrap(),
        );
    }

    Ok(response)
}

/// Handle rate limiting errors
fn handle_rate_limit_error(
    error: RateLimitError,
    target_host: &str,
    token_id: &str,
    start_time: std::time::Instant,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let duration = start_time.elapsed();

    match error {
        RateLimitError::LimitExceeded(_) => {
            warn!("[CONNECT] Rate limit exceeded for {} - token_id={} (duration={:?})",
                target_host, token_id, duration);

            Ok(Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Full::new(Bytes::from(
                    "Rate limit exceeded. Please retry later."
                )))
                .unwrap())
        },
        RateLimitError::TooManyTokens(max) => {
            error!("[CONNECT] Too many tokens error for {} - max={} (duration={:?})",
                target_host, max, duration);

            Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from(
                    format!("Service temporarily unavailable. Maximum {} concurrent tokens.", max)
                )))
                .unwrap())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use http_body_util::BodyExt;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use crate::auth::{JwtClaims, JwtValidator};
    use crate::rate_limiter::{RateLimiter, RateLimiterConfig};

    // Helper to create a test config
    fn create_test_config() -> Arc<Config> {
        let jwt_validator = Arc::new(JwtValidator::new(
            "test_secret_key_32_chars_minimum!!".to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            None, // No issuer validation in tests
            None, // No audience validation in tests
        ).unwrap());

        let rate_limiter_config = RateLimiterConfig {
            requests_per_minute: 60,
            burst_size: 10,
            bucket_ttl_seconds: 60,
            max_buckets: 100,
        };
        let rate_limiter = Arc::new(RateLimiter::new(rate_limiter_config));

        Arc::new(Config {
            host: "127.0.0.1".to_string(),
            port: 443,
            cert_path: "".to_string(),
            key_path: "".to_string(),
            jwt_secret: "test_secret_key_32_chars_minimum!!".to_string(),
            jwt_algorithm: "HS256".to_string(),
            rate_limit_requests_per_minute: 60,
            rate_limit_burst_size: 10,
            rate_limit_bucket_ttl_seconds: 60,
            rate_limit_max_buckets: 100,
            backend_url: "http://localhost:8000".to_string(),
            probe_node_name: "test-node".to_string(),
            probe_node_region: "us-east".to_string(),
            log_batch_size: 100,
            log_batch_interval_secs: 5,
            jwt_validator,
            rate_limiter,
        })
    }

    // Helper to create a valid JWT token
    fn create_test_token(secret: &str, allowed_regions: Vec<String>) -> String {
        let claims = JwtClaims {
            token_id: "test_token_123".to_string(),
            user_id: 42,
            allowed_regions,
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            iss: None,
            aud: None,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap()
    }

    // Note: Full integration tests for handle_request and handle_connect would require
    // setting up actual TCP connections and Hyper servers. Instead, we test the
    // error handler functions directly which cover all the critical logic paths.

    #[test]
    fn test_parse_authority_valid() {
        // Valid host:port
        assert_eq!(
            parse_authority("example.com:443"),
            Ok(("example.com".to_string(), 443))
        );

        // IPv4 with port
        assert_eq!(
            parse_authority("192.168.1.1:8080"),
            Ok(("192.168.1.1".to_string(), 8080))
        );

        // IPv6 with port (simplified, real IPv6 would be [::1]:443)
        assert_eq!(
            parse_authority("[::1]:443"),
            Ok(("[::1]".to_string(), 443))
        );

        // High port number
        assert_eq!(
            parse_authority("example.com:65535"),
            Ok(("example.com".to_string(), 65535))
        );

        // Low port number
        assert_eq!(
            parse_authority("example.com:1"),
            Ok(("example.com".to_string(), 1))
        );
    }

    #[test]
    fn test_parse_authority_invalid() {
        // Missing port
        assert!(parse_authority("example.com").is_err());

        // Empty host
        assert!(parse_authority(":443").is_err());

        // Empty string
        assert!(parse_authority("").is_err());

        // Port is zero
        assert!(parse_authority("example.com:0").is_err());

        // Port is not a number
        assert!(parse_authority("example.com:abc").is_err());

        // Port out of range (too high)
        assert!(parse_authority("example.com:65536").is_err());

        // Port is negative (will fail parse)
        assert!(parse_authority("example.com:-1").is_err());

        // Multiple colons without brackets
        assert!(parse_authority("example.com:80:443").is_ok()); // Will take last :443

        // No colon separator
        assert!(parse_authority("example_com_443").is_err());
    }

    #[tokio::test]
    async fn test_handle_auth_error_messages() {
        // Test that error messages are descriptive
        let error = AuthError::MissingHeader;
        let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        let error = AuthError::InvalidFormat;
        let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let error = AuthError::TokenExpired;
        let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

        let error = AuthError::ValidationFailed("test".to_string());
        let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let error = AuthError::RegionNotAllowed("us-west".to_string());
        let response = handle_auth_error(error, "example.com:443", std::time::Instant::now()).unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_rate_limit_errors() {
        use crate::rate_limiter::RateLimitError;

        // Test LimitExceeded error
        let error = RateLimitError::LimitExceeded("Rate limit exceeded".to_string());
        let response = handle_rate_limit_error(
            error,
            "example.com:443",
            "test_token",
            std::time::Instant::now()
        ).unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // Test TooManyTokens error
        let error = RateLimitError::TooManyTokens(1000);
        let response = handle_rate_limit_error(
            error,
            "example.com:443",
            "test_token",
            std::time::Instant::now()
        ).unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // Phase 3 Integration Tests
    // These tests exercise the full CONNECT handler flow through handle_connect()
    // Testing: auth validation, rate limiting, authority parsing, and error responses

    #[tokio::test]
    async fn test_connect_flow_missing_auth() {
        // Integration Test: CONNECT without Proxy-Authorization should return 407 with Bearer challenge
        let config = create_test_config();

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(response.headers().contains_key("proxy-authenticate"));
        assert_eq!(
            response.headers().get("proxy-authenticate").unwrap(),
            "Bearer realm=\"ProbeOps Forward Proxy\""
        );

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Proxy-Authorization"));
    }

    #[tokio::test]
    async fn test_connect_flow_invalid_auth_format() {
        // Integration Test: Malformed Proxy-Authorization should return 400
        let config = create_test_config();

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header("Proxy-Authorization", "Invalid Token Format")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Bearer"));
    }

    #[tokio::test]
    async fn test_connect_flow_expired_token() {
        // Integration Test: Expired JWT should return 407
        let config = create_test_config();
        let secret = "test_secret_key_32_chars_minimum!!";

        let claims = JwtClaims {
            token_id: "test_token_expired".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (Utc::now() - chrono::Duration::hours(1)).timestamp(),
            iat: (Utc::now() - chrono::Duration::hours(2)).timestamp(),
            iss: None,
            aud: None,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(response.headers().contains_key("proxy-authenticate"));
    }

    #[tokio::test]
    async fn test_connect_flow_wrong_region() {
        // Integration Test: Token with wrong region should return 403
        let config = create_test_config();
        let secret = "test_secret_key_32_chars_minimum!!";

        // Token for eu-west, but config expects us-east
        let token = create_test_token(secret, vec!["eu-west".to_string()]);

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Region") || body_str.contains("denied"));
    }

    #[tokio::test]
    async fn test_connect_flow_wildcard_region_passes_auth() {
        // Integration Test: Token with ["*"] should pass region check for any region
        let config = create_test_config();
        let secret = "test_secret_key_32_chars_minimum!!";

        let token = create_test_token(secret, vec!["*".to_string()]);

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("127.0.0.1:1234") // Use unreachable address for test
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        // Should pass auth (wildcard allows all regions)
        // Will be 502 Bad Gateway because 127.0.0.1:1234 is unreachable
        // But NOT 403 Forbidden or 407 Auth Required
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        assert_ne!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }

    #[tokio::test]
    async fn test_connect_flow_malformed_authorities() {
        // Integration Test: Various malformed authorities should return 400
        let config = create_test_config();
        let secret = "test_secret_key_32_chars_minimum!!";
        let token = create_test_token(secret, vec!["us-east".to_string()]);

        let test_cases = vec![
            ("example.com", "Missing port"),
            (":443", "Empty host"),
            ("example.com:abc", "Non-numeric port"),
            ("example.com:0", "Port zero"),
            ("example.com:99999", "Port out of range"),
        ];

        for (authority, description) in test_cases {
            let mut req = Request::builder()
                .method(Method::CONNECT)
                .uri(authority)
                .header("Proxy-Authorization", format!("Bearer {}", token))
                .body(Empty::<Bytes>::new())
                .unwrap();

            let response = handle_connect(req, config.clone()).await.unwrap();

            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{}: Authority '{}' should return 400",
                description,
                authority
            );

            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes);
            assert!(
                body_str.contains("Bad Request") || body_str.contains("Invalid"),
                "{}: Should have error in body",
                description
            );
        }
    }

    #[tokio::test]
    async fn test_connect_flow_valid_auth_attempts_upstream() {
        // Integration Test: Valid auth + valid authority should attempt upstream connection
        let config = create_test_config();
        let secret = "test_secret_key_32_chars_minimum!!";
        let token = create_test_token(secret, vec!["us-east".to_string()]);

        let mut req = Request::builder()
            .method(Method::CONNECT)
            .uri("127.0.0.1:1") // Unreachable address
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = handle_connect(req, config).await.unwrap();

        // Should pass auth (not 407) and authority validation (not 400)
        assert_ne!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
        assert_ne!(response.status(), StatusCode::BAD_REQUEST);

        // Will be 502 Bad Gateway because upstream is unreachable
        // or 200 if upgrade somehow succeeds (shouldn't in tests)
        assert!(
            response.status() == StatusCode::OK
                || response.status() == StatusCode::BAD_GATEWAY,
            "Expected 200 or 502, got {}",
            response.status()
        );
    }
}
