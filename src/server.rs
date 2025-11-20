use anyhow::Result;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
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
async fn handle_connect(
    mut req: Request<Incoming>,
    config: Arc<Config>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = std::time::Instant::now();
    let target_host = req.uri().authority()
        .map(|auth| auth.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    info!("[CONNECT] {} from client", target_host);

    // Phase 3.1: JWT Authentication
    let claims = match config.jwt_validator.validate_request(&req) {
        Ok(claims) => claims,
        Err(e) => {
            return handle_auth_error(e, &target_host, start_time);
        }
    };

    debug!("[CONNECT] Authenticated user_id={}, token_id={}",
        claims.user_id, claims.token_id);

    // Phase 3.2: Region Access Validation
    if !claims.allowed_regions.contains(&config.probe_node_region)
        && !claims.allowed_regions.contains(&"*".to_string()) {
        warn!("[CONNECT] Region access denied for {} - allowed: {:?}, current: {}",
            target_host, claims.allowed_regions, config.probe_node_region);

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(
                "Access denied: Region not in allowed list"
            )))
            .unwrap());
    }

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
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            "Proxy-Authenticate",
            "Basic realm=\"ProbeOps Forward Proxy\"".parse().unwrap(),
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

    #[tokio::test]
    async fn test_server_placeholder() {
        // Placeholder test
        // Real tests will be added when handlers are implemented
        assert!(true);
    }
}
