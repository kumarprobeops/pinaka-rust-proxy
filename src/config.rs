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
            jwt_issuer.clone(),
            jwt_audience.clone(),
        )
        .context("Failed to initialize JWT validator")?;

        // Security warning: Log if issuer/audience validation is disabled
        if jwt_issuer.is_none() || jwt_audience.is_none() {
            tracing::warn!(
                issuer_set = jwt_issuer.is_some(),
                audience_set = jwt_audience.is_some(),
                "⚠️  JWT issuer/audience validation is DISABLED. Any token signed with the correct secret will be accepted. \
                 Set JWT_ISSUER and JWT_AUDIENCE environment variables for production deployments. \
                 See docs/JWT_VALIDATION_DEPLOYMENT_GUIDE.md for details."
            );
        } else {
            tracing::info!(
                issuer = jwt_issuer.as_deref().unwrap(),
                audience = jwt_audience.as_deref().unwrap(),
                "✓ JWT validation configured with issuer and audience enforcement"
            );
        }

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
    use std::env;
    use std::sync::Mutex;

    // Global mutex to serialize config tests (env vars are process-global)
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    // Helper to setup minimal valid test environment
    fn setup_test_env() {
        env::set_var("JWT_SECRET", "valid_test_secret_32_chars_min!!");
        env::set_var("PROBE_NODE_REGION", "test-region");
    }

    // Helper to clear test environment
    fn clear_test_env() {
        env::remove_var("JWT_SECRET");
        env::remove_var("JWT_ISSUER");
        env::remove_var("JWT_AUDIENCE");
        env::remove_var("PROBE_NODE_REGION");
    }

    #[test]
    fn test_config_from_env_rejects_empty_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject empty JWT_SECRET
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "");
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(result.is_err(), "Empty JWT_SECRET should be rejected");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JWT_SECRET cannot be empty"),
            "Error message should mention empty secret: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_rejects_whitespace_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject whitespace-only JWT_SECRET
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "   ");
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(result.is_err(), "Whitespace-only JWT_SECRET should be rejected");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JWT_SECRET cannot be empty"),
            "Error message should mention empty secret: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_rejects_short_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should reject JWT_SECRET < 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "short_secret_19chars"); // 19 chars
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(result.is_err(), "JWT_SECRET shorter than 32 chars should be rejected");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too short") && err_msg.contains("32 characters"),
            "Error message should mention minimum length: {}",
            err_msg
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_accepts_minimum_length_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should accept JWT_SECRET with exactly 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        env::set_var("JWT_SECRET", "exactly_32_characters_long_yes!!"); // Exactly 32 chars
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "JWT_SECRET with exactly 32 chars should be accepted: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert_eq!(config.jwt_secret, "exactly_32_characters_long_yes!!");

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_accepts_long_jwt_secret() {
        // Phase 2.2 Integration Test: Config::from_env() should accept JWT_SECRET > 32 chars
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        let long_secret = "this_is_a_very_long_jwt_secret_with_more_than_32_characters_for_security";
        env::set_var("JWT_SECRET", long_secret);
        env::set_var("PROBE_NODE_REGION", "test-region");

        let result = Config::from_env();
        assert!(
            result.is_ok(),
            "JWT_SECRET longer than 32 chars should be accepted: {:?}",
            result.err()
        );

        let config = result.unwrap();
        assert_eq!(config.jwt_secret, long_secret);

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_issuer_audience_optional() {
        // Phase 2.2 Integration Test: JWT_ISSUER and JWT_AUDIENCE should be optional
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        setup_test_env();

        // Without JWT_ISSUER/JWT_AUDIENCE set
        let result = Config::from_env();
        assert!(result.is_ok(), "Config should succeed without JWT_ISSUER/JWT_AUDIENCE");

        let config = result.unwrap();
        assert!(
            config.jwt_validator.expected_issuer().is_none(),
            "expected_issuer should be None when JWT_ISSUER not set"
        );
        assert!(
            config.jwt_validator.expected_audience().is_none(),
            "expected_audience should be None when JWT_AUDIENCE not set"
        );

        clear_test_env();
    }

    #[test]
    fn test_config_from_env_issuer_audience_configured() {
        // Phase 2.2 Integration Test: JWT_ISSUER and JWT_AUDIENCE should be configurable
        let _lock = TEST_MUTEX.lock().unwrap();
        clear_test_env();
        setup_test_env();
        env::set_var("JWT_ISSUER", "test-issuer");
        env::set_var("JWT_AUDIENCE", "test-audience");

        let result = Config::from_env();
        assert!(result.is_ok(), "Config should succeed with JWT_ISSUER/JWT_AUDIENCE");

        let config = result.unwrap();
        assert_eq!(
            config.jwt_validator.expected_issuer(),
            Some("test-issuer"),
            "expected_issuer should match JWT_ISSUER env var"
        );
        assert_eq!(
            config.jwt_validator.expected_audience(),
            Some("test-audience"),
            "expected_audience should match JWT_AUDIENCE env var"
        );

        clear_test_env();
    }
}
