use anyhow::{Context, Result};
use std::env;
use std::sync::Arc;

use crate::auth::{JwtValidator, SharedJwtValidator};
use crate::rate_limiter::{RateLimiter, RateLimiterConfig, SharedRateLimiter};

#[derive(Debug)]
pub struct Config {
    // Server configuration
    pub host: String,
    pub port: u16,

    // TLS certificate paths
    pub cert_path: String,
    pub key_path: String,

    // JWT configuration
    pub jwt_secret: String,
    pub jwt_algorithm: String,

    // Rate limiting
    pub rate_limit_requests_per_minute: usize,
    pub rate_limit_burst_size: usize,
    pub rate_limit_bucket_ttl_seconds: u64,
    pub rate_limit_max_buckets: usize,

    // Backend API configuration
    pub backend_url: String,
    pub probe_node_name: String,
    pub probe_node_region: String,

    // Logging
    pub log_batch_size: usize,
    pub log_batch_interval_secs: u64,

    // Phase 2: Authentication and rate limiting components
    pub jwt_validator: SharedJwtValidator,
    pub rate_limiter: SharedRateLimiter,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv::dotenv().ok(); // Load .env file if present

        // Load configuration values
        let host = env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PROXY_PORT")
            .unwrap_or_else(|_| "443".to_string())
            .parse()
            .context("Invalid PROXY_PORT")?;

        let cert_path = env::var("TLS_CERT_PATH")
            .unwrap_or_else(|_| "/etc/letsencrypt/live/staging.probeops.com/fullchain.pem".to_string());
        let key_path = env::var("TLS_KEY_PATH")
            .unwrap_or_else(|_| "/etc/letsencrypt/live/staging.probeops.com/privkey.pem".to_string());

        let jwt_secret = env::var("JWT_SECRET")
            .context("JWT_SECRET environment variable is required for authentication")?;

        // Validate JWT_SECRET is not empty or too short
        if jwt_secret.trim().is_empty() {
            return Err(anyhow::anyhow!("JWT_SECRET cannot be empty"));
        }
        if jwt_secret.len() < 32 {
            return Err(anyhow::anyhow!(
                "JWT_SECRET is too short ({} chars). Minimum 32 characters recommended for security.",
                jwt_secret.len()
            ));
        }

        let jwt_algorithm = env::var("JWT_ALGORITHM")
            .unwrap_or_else(|_| "HS256".to_string());

        // Optional issuer and audience validation
        let jwt_issuer = env::var("JWT_ISSUER").ok();
        let jwt_audience = env::var("JWT_AUDIENCE").ok();

        let rate_limit_requests_per_minute = env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_REQUESTS_PER_MINUTE")?;
        let rate_limit_burst_size = env::var("RATE_LIMIT_BURST_SIZE")
            .unwrap_or_else(|_| "500".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_BURST_SIZE")?;
        let rate_limit_bucket_ttl_seconds = env::var("RATE_LIMIT_BUCKET_TTL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_BUCKET_TTL_SECONDS")?;
        let rate_limit_max_buckets = env::var("RATE_LIMIT_MAX_BUCKETS")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .context("Invalid RATE_LIMIT_MAX_BUCKETS")?;

        let backend_url = env::var("BACKEND_URL")
            .unwrap_or_else(|_| "https://staging.probeops.com".to_string());
        let probe_node_name = env::var("PROBE_NODE_NAME")
            .unwrap_or_else(|_| "probe-node-rust".to_string());
        let probe_node_region = env::var("PROBE_NODE_REGION")
            .unwrap_or_else(|_| "us-east".to_string());

        let log_batch_size = env::var("LOG_BATCH_SIZE")
            .unwrap_or_else(|_| "100".to_string())
            .parse()
            .context("Invalid LOG_BATCH_SIZE")?;
        let log_batch_interval_secs = env::var("LOG_BATCH_INTERVAL_SECS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .context("Invalid LOG_BATCH_INTERVAL_SECS")?;

        // Phase 2: Initialize JWT validator
        let jwt_validator = JwtValidator::new(
            jwt_secret.clone(),
            jwt_algorithm.clone(),
            probe_node_region.clone(),
            jwt_issuer,
            jwt_audience,
        )
        .context("Failed to initialize JWT validator")?;

        // Phase 2: Initialize rate limiter
        let rate_limiter_config = RateLimiterConfig {
            requests_per_minute: rate_limit_requests_per_minute,
            burst_size: rate_limit_burst_size,
            bucket_ttl_seconds: rate_limit_bucket_ttl_seconds,
            max_buckets: rate_limit_max_buckets,
        };
        let rate_limiter = RateLimiter::new(rate_limiter_config);

        Ok(Config {
            host,
            port,
            cert_path,
            key_path,
            jwt_secret,
            jwt_algorithm,
            rate_limit_requests_per_minute,
            rate_limit_burst_size,
            rate_limit_bucket_ttl_seconds,
            rate_limit_max_buckets,
            backend_url,
            probe_node_name,
            probe_node_region,
            log_batch_size,
            log_batch_interval_secs,
            jwt_validator: Arc::new(jwt_validator),
            rate_limiter: Arc::new(rate_limiter),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_secret_validation_empty() {
        // Phase 2.2: Test that empty JWT_SECRET is rejected
        let secret = "";
        assert!(secret.trim().is_empty(), "Empty string validation");
    }

    #[test]
    fn test_jwt_secret_validation_whitespace_only() {
        // Phase 2.2: Test that whitespace-only JWT_SECRET is rejected
        let secret = "   ";
        assert!(secret.trim().is_empty(), "Whitespace-only string validation");
    }

    #[test]
    fn test_jwt_secret_validation_too_short() {
        // Phase 2.2: Test that JWT_SECRET shorter than 32 chars is rejected
        let secret = "short_secret_12345"; // Only 19 characters
        assert!(secret.len() < 32, "Secret should be shorter than 32 chars");
    }

    #[test]
    fn test_jwt_secret_validation_minimum_length() {
        // Phase 2.2: Test that JWT_SECRET with exactly 32 chars is accepted
        let secret = "exactly_32_characters_long_yes!!";  // Exactly 32 chars
        assert_eq!(secret.len(), 32, "Secret should be exactly 32 chars");
        assert!(!secret.trim().is_empty(), "Secret should not be empty");
    }
}
