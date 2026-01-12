//! Rate limiting module
//!
//! Provides token bucket rate limiting for MQTT message publishing.

mod limiter;

pub use limiter::RateLimiter;
