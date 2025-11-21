// Library exports for testing
// Exposes internal modules for integration and security tests

pub mod config;
pub mod auth;
pub mod rate_limiter;
pub mod destination_filter;
pub mod ip_tracker;
pub mod body_limiter;
pub mod http_metrics;
pub mod http_client;
pub mod logger;

// Re-export commonly used types for testing
pub use destination_filter::{DestinationFilter, DestinationError};
pub use ip_tracker::{IpTracker, IpTrackerError};
pub use body_limiter::{read_body_with_limit, BodyLimitError};
