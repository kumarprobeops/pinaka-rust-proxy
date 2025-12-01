use anyhow::{Context, Result};
use std::sync::Arc;

// ProbeOps-specific modules (extended functionality)
use crate::auth::{JwtValidator, SharedJwtValidator};
use crate::rate_limiter::{RateLimiter, RateLimiterConfig, SharedRateLimiter};
use crate::logger::{RequestLogger, SharedRequestLogger};

/// ProbeOps Configuration
/// Wraps derusted::Config and adds ProbeOps-specific extensions
#[derive(Debug)]
pub struct Config {
    /// Base derusted configuration - used for HTTP forwarding, mixed content, etc.
    pub base: derusted::Config,

    /// ProbeOps JWT validator with extended claims (rate_limit_per_hour, concurrent_tabs)
    pub jwt_validator: SharedJwtValidator,

    /// ProbeOps rate limiter with dynamic tier-based limits (check_limit_with_override)
    pub rate_limiter: SharedRateLimiter,

    /// ProbeOps request logger for analytics
    pub request_logger: SharedRequestLogger,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        // Load base derusted configuration from environment
        let base = derusted::Config::from_env()
            .context("Failed to load derusted base configuration")?;

        // Initialize ProbeOps JWT validator (with extended claims support)
        // This extends derusted's validator with rate_limit_per_hour and concurrent_tabs
        let jwt_validator = JwtValidator::new(
            base.jwt_secret.clone(),
            base.jwt_algorithm.clone(),
            base.probe_node_region.clone(),
            // Optional issuer/audience from environment
            std::env::var("JWT_ISSUER").ok(),
            std::env::var("JWT_AUDIENCE").ok(),
        ).context("Failed to initialize ProbeOps JWT validator")?;

        // Initialize ProbeOps rate limiter (with dynamic tier support)
        // This extends derusted's rate limiter with check_limit_with_override
        let rate_limiter_config = RateLimiterConfig {
            requests_per_minute: base.rate_limit_requests_per_minute,
            burst_size: base.rate_limit_burst_size,
            bucket_ttl_seconds: base.rate_limit_bucket_ttl_seconds,
            max_buckets: base.rate_limit_max_buckets,
        };
        let rate_limiter = RateLimiter::new(rate_limiter_config);

        // Initialize ProbeOps request logger
        let request_logger = RequestLogger::new(
            base.backend_url.clone(),
            base.probe_node_name.clone(),
            base.probe_node_region.clone(),
            base.log_batch_size,
            base.log_batch_interval_secs,
        );

        Ok(Config {
            base,
            jwt_validator: Arc::new(jwt_validator),
            rate_limiter: Arc::new(rate_limiter),
            request_logger: Arc::new(request_logger),
        })
    }

    // Convenience accessors for commonly used base config fields
    pub fn host(&self) -> &str { &self.base.host }
    pub fn port(&self) -> u16 { self.base.port }
    pub fn cert_path(&self) -> &str { &self.base.cert_path }
    pub fn key_path(&self) -> &str { &self.base.key_path }
    pub fn http_proxy_enabled(&self) -> bool { self.base.http_proxy_enabled }
    pub fn max_request_body_size(&self) -> usize { self.base.max_request_body_size }
    pub fn probe_node_region(&self) -> &str { &self.base.probe_node_region }
    pub fn log_batch_size(&self) -> usize { self.base.log_batch_size }
    pub fn log_batch_interval_secs(&self) -> u64 { self.base.log_batch_interval_secs }
}
