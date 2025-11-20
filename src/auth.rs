// JWT Authentication Module
// Phase 2: JWT token validation for forward proxy authentication

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingHeader,

    #[error("Invalid authorization format (expected: Bearer <token>)")]
    InvalidFormat,

    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Region not allowed: {0}")]
    RegionNotAllowed(String),
}

/// JWT Claims structure matching backend token format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Unique token identifier
    pub token_id: String,

    /// User ID who owns the token
    pub user_id: i32,

    /// List of allowed regions (e.g., ["us-east", "eu-west"])
    pub allowed_regions: Vec<String>,

    /// Token expiration (Unix timestamp)
    pub exp: i64,

    /// Token issued at (Unix timestamp)
    pub iat: i64,

    /// Issuer (e.g., "probeops")
    #[serde(default)]
    pub iss: Option<String>,
}

/// JWT Validator with configuration
#[derive(Debug)]
pub struct JwtValidator {
    secret: String,
    algorithm: Algorithm,
    current_region: String,
}

impl JwtValidator {
    /// Create a new JWT validator
    pub fn new(secret: String, algorithm: String, current_region: String) -> Result<Self> {
        let algo = match algorithm.to_uppercase().as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            _ => return Err(anyhow!("Unsupported JWT algorithm: {}", algorithm)),
        };

        Ok(Self {
            secret,
            algorithm: algo,
            current_region,
        })
    }

    /// Extract Bearer token from Authorization header value
    fn extract_bearer_token(auth_header: &str) -> Result<&str, AuthError> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();

        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        if parts[0].to_lowercase() != "bearer" {
            return Err(AuthError::InvalidFormat);
        }

        Ok(parts[1])
    }

    /// Validate JWT token from Authorization header
    pub fn validate(&self, auth_header: &str) -> Result<JwtClaims, AuthError> {
        // Extract token from "Bearer <token>" format
        let token = Self::extract_bearer_token(auth_header)?;

        // Configure validation
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = false; // Not Before is optional

        // Decode and validate token
        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());
        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::ValidationFailed(e.to_string()))?;

        let claims = token_data.claims;

        // Check if current region is allowed
        if !claims.allowed_regions.is_empty()
            && !claims.allowed_regions.contains(&self.current_region)
        {
            return Err(AuthError::RegionNotAllowed(self.current_region.clone()));
        }

        Ok(claims)
    }

    /// Validate token from HTTP request (extracts header)
    pub fn validate_request<T>(&self, request: &http::Request<T>) -> Result<JwtClaims, AuthError> {
        // Check for Proxy-Authorization header first (standard for proxies)
        let auth_header = request
            .headers()
            .get("proxy-authorization")
            .or_else(|| request.headers().get("authorization"))
            .ok_or(AuthError::MissingHeader)?;

        let auth_str = auth_header
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        self.validate(auth_str)
    }
}

/// Thread-safe JWT validator (can be shared across async tasks)
pub type SharedJwtValidator = Arc<JwtValidator>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        // Valid format
        let result = JwtValidator::extract_bearer_token("Bearer abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");

        // Case insensitive
        let result = JwtValidator::extract_bearer_token("bearer xyz789");
        assert!(result.is_ok());

        // Invalid format
        let result = JwtValidator::extract_bearer_token("abc123");
        assert!(result.is_err());

        let result = JwtValidator::extract_bearer_token("Basic abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_validator_creation() {
        let validator = JwtValidator::new(
            "test_secret".to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
        );
        assert!(validator.is_ok());

        let validator = JwtValidator::new(
            "test_secret".to_string(),
            "INVALID".to_string(),
            "us-east".to_string(),
        );
        assert!(validator.is_err());
    }

    #[test]
    fn test_region_validation() {
        // This test would require a valid JWT token
        // For now, it's a placeholder for future integration tests
        // Real JWT tokens will be tested in integration tests with actual backend tokens
    }
}
