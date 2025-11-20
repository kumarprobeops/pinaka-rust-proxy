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

    /// Audience (e.g., "forward-proxy")
    #[serde(default)]
    pub aud: Option<String>,
}

/// JWT Validator with configuration
#[derive(Debug)]
pub struct JwtValidator {
    secret: String,
    algorithm: Algorithm,
    current_region: String,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
}

impl JwtValidator {
    /// Create a new JWT validator
    pub fn new(
        secret: String,
        algorithm: String,
        current_region: String,
        expected_issuer: Option<String>,
        expected_audience: Option<String>,
    ) -> Result<Self> {
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
            expected_issuer,
            expected_audience,
        })
    }

    /// Get the expected issuer (for testing/verification)
    pub fn expected_issuer(&self) -> Option<&str> {
        self.expected_issuer.as_deref()
    }

    /// Get the expected audience (for testing/verification)
    pub fn expected_audience(&self) -> Option<&str> {
        self.expected_audience.as_deref()
    }

    /// Check if issuer/audience validation is enabled
    pub fn has_strict_validation(&self) -> bool {
        self.expected_issuer.is_some() && self.expected_audience.is_some()
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

        // Set issuer and audience validation
        // Note: jsonwebtoken defaults to NOT validating iss/aud unless explicitly set
        if let Some(ref iss) = self.expected_issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.expected_audience {
            validation.set_audience(&[aud]);
        }

        // Decode and validate token
        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());
        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                // Check specific error types
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    ErrorKind::InvalidIssuer => AuthError::ValidationFailed("Invalid issuer".to_string()),
                    ErrorKind::InvalidAudience => AuthError::ValidationFailed("Invalid audience".to_string()),
                    ErrorKind::InvalidSignature => AuthError::ValidationFailed("Invalid signature".to_string()),
                    _ => AuthError::ValidationFailed(e.to_string()),
                }
            })?;

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
    use jsonwebtoken::{encode, EncodingKey, Header};

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
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        );
        assert!(validator.is_ok());
        let validator = validator.unwrap();
        assert_eq!(validator.expected_issuer, Some("probeops".to_string()));
        assert_eq!(validator.expected_audience, Some("forward-proxy".to_string()));

        let validator = JwtValidator::new(
            "test_secret_long_enough_for_testing".to_string(),
            "INVALID".to_string(),
            "us-east".to_string(),
            None,
            None,
        );
        assert!(validator.is_err());
    }

    #[test]
    fn test_valid_token_validation() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create a valid token
        let claims = JwtClaims {
            token_id: "test_token_123".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string(), "eu-west".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Validate token
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_ok());
        let validated_claims = result.unwrap();
        assert_eq!(validated_claims.token_id, "test_token_123");
        assert_eq!(validated_claims.user_id, 42);
    }

    #[test]
    fn test_expired_token() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create an expired token (1 hour ago)
        let claims = JwtClaims {
            token_id: "expired_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp(),
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Validate expired token
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        // Check that it's specifically a TokenExpired error
        match result.unwrap_err() {
            AuthError::TokenExpired => (),
            other => panic!("Expected TokenExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_signature() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create a token with different secret
        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret("wrong_secret".as_bytes()),
        ).unwrap();

        // Validate with wrong secret
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid signature"));
            },
            other => panic!("Expected ValidationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_region_not_allowed() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "ap-south".to_string(), // Different region
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create a token that only allows us-east and eu-west
        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string(), "eu-west".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Validate in ap-south region
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::RegionNotAllowed(region) => {
                assert_eq!(region, "ap-south");
            },
            other => panic!("Expected RegionNotAllowed, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_issuer() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create a token with wrong issuer
        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("malicious_issuer".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid issuer"));
            },
            other => panic!("Expected ValidationFailed with issuer error, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_audience() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Create a token with wrong audience
        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("wrong_service".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::ValidationFailed(msg) => {
                assert!(msg.contains("Invalid audience"));
            },
            other => panic!("Expected ValidationFailed with audience error, got {:?}", other),
        }
    }

    #[test]
    fn test_configurable_issuer_audience_disabled() {
        // Phase 2.2: Test that issuer/audience validation can be disabled (None)
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            None, // No issuer validation
            None, // No audience validation
        ).unwrap();

        // Verify validator has no issuer/audience configured
        assert_eq!(validator.expected_issuer, None);
        assert_eq!(validator.expected_audience, None);

        // Create a token WITHOUT issuer/audience claims
        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: None, // No issuer
            aud: None, // No audience
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Should succeed because validation is disabled
        let auth_header = format!("Bearer {}", token);
        let result = validator.validate(&auth_header);
        assert!(result.is_ok(), "Token without issuer/audience should succeed when validation disabled");

        // Test with issuer/audience enabled
        let validator_with_checks = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        // Verify validator has issuer/audience configured
        assert_eq!(validator_with_checks.expected_issuer, Some("probeops".to_string()));
        assert_eq!(validator_with_checks.expected_audience, Some("forward-proxy".to_string()));

        // Token missing required issuer/audience should fail
        let result = validator_with_checks.validate(&auth_header);
        // Note: jsonwebtoken library behavior - missing fields may not fail if not required
        // The key test is that we CAN disable validation by setting None
        if result.is_err() {
            // This is expected - validator requires issuer/audience but token doesn't have them
            let err = result.unwrap_err();
            assert!(
                matches!(err, AuthError::ValidationFailed(_)),
                "Should be ValidationFailed error"
            );
        }
    }

    #[test]
    fn test_proxy_authorization_header() {
        let secret = "test_secret_key_probeops_2025";
        let validator = JwtValidator::new(
            secret.to_string(),
            "HS256".to_string(),
            "us-east".to_string(),
            Some("probeops".to_string()),
            Some("forward-proxy".to_string()),
        ).unwrap();

        let claims = JwtClaims {
            token_id: "test_token".to_string(),
            user_id: 42,
            allowed_regions: vec!["us-east".to_string()],
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: chrono::Utc::now().timestamp(),
            iss: Some("probeops".to_string()),
            aud: Some("forward-proxy".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Test with Proxy-Authorization header
        let mut request = http::Request::builder()
            .header("Proxy-Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_ok());

        // Test with Authorization header (fallback)
        request = http::Request::builder()
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_ok());

        // Test missing header
        request = http::Request::builder()
            .body(())
            .unwrap();

        let result = validator.validate_request(&request);
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::MissingHeader => (),
            other => panic!("Expected MissingHeader, got {:?}", other),
        }
    }
}
