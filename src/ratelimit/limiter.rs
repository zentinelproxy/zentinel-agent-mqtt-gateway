//! Token bucket rate limiter

use crate::config::{ConnectionContext, RateLimit, RateLimitConfig, RateLimitKey};
use crate::mqtt::TopicMatcher;
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovRateLimiter,
};
use nonzero_ext::nonzero;
use parking_lot::RwLock;
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::debug;

/// Rate limit check result
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Which limit was exceeded (if any)
    pub exceeded_limit: Option<String>,
    /// Suggested retry delay in milliseconds
    pub retry_after_ms: Option<u64>,
}

impl RateLimitResult {
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            exceeded_limit: None,
            retry_after_ms: None,
        }
    }

    pub fn denied(limit_name: &str, retry_after_ms: Option<u64>) -> Self {
        Self {
            allowed: false,
            exceeded_limit: Some(limit_name.to_string()),
            retry_after_ms,
        }
    }
}

type SharedLimiter = Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

/// Per-client rate limiter entry
struct ClientLimiter {
    messages: Option<SharedLimiter>,
    bytes: Option<SharedLimiter>,
}

/// Rate limiter for MQTT messages
pub struct RateLimiter {
    config: Arc<RwLock<RateLimitConfig>>,
    /// Global rate limiter (shared across all clients)
    global_limiter: RwLock<Option<ClientLimiter>>,
    /// Per-client rate limiters
    client_limiters: DashMap<String, ClientLimiter>,
    /// Per-topic rate limiters
    topic_limiters: DashMap<String, ClientLimiter>,
    /// Topic matcher for topic patterns
    topic_matcher: TopicMatcher,
}

impl RateLimiter {
    /// Create a new rate limiter from configuration
    pub fn new(config: &RateLimitConfig) -> Self {
        let global_limiter = config.global.as_ref().map(create_limiter_pair);

        Self {
            config: Arc::new(RwLock::new(config.clone())),
            global_limiter: RwLock::new(global_limiter),
            client_limiters: DashMap::new(),
            topic_limiters: DashMap::new(),
            topic_matcher: TopicMatcher::new(),
        }
    }

    /// Check if a message is allowed
    pub fn check_message(
        &self,
        context: &ConnectionContext,
        topic: &str,
        payload_size: usize,
    ) -> RateLimitResult {
        let config = self.config.read();

        if !config.enabled {
            return RateLimitResult::allowed();
        }

        // Check global limit
        if let Some(ref limiter) = *self.global_limiter.read() {
            if !check_limiter(limiter, payload_size) {
                debug!("Global rate limit exceeded");
                return RateLimitResult::denied("global", Some(1000));
            }
        }

        // Check per-client limit
        if let Some(ref limit) = config.per_client {
            let key = self.get_client_key(context, &config.key_by);

            let limiter = self.client_limiters.entry(key.clone()).or_insert_with(|| {
                create_limiter_pair(limit)
            });

            if !check_limiter(&limiter, payload_size) {
                debug!(client = %key, "Per-client rate limit exceeded");
                return RateLimitResult::denied(&format!("per-client:{}", key), Some(1000));
            }
        }

        // Check per-topic limits
        for topic_limit in &config.per_topic {
            if self.topic_matcher.matches(topic, &topic_limit.topic) {
                let limiter = self.topic_limiters.entry(topic_limit.topic.clone()).or_insert_with(|| {
                    create_limiter_pair(&topic_limit.limit)
                });

                if !check_limiter(&limiter, payload_size) {
                    debug!(topic = %topic, pattern = %topic_limit.topic, "Per-topic rate limit exceeded");
                    return RateLimitResult::denied(&format!("per-topic:{}", topic_limit.topic), Some(1000));
                }
            }
        }

        RateLimitResult::allowed()
    }

    /// Get the client key for rate limiting
    fn get_client_key(&self, context: &ConnectionContext, key_by: &RateLimitKey) -> String {
        match key_by {
            RateLimitKey::ClientId => context.client_id.clone(),
            RateLimitKey::Username => context.username.clone().unwrap_or_else(|| "anonymous".to_string()),
            RateLimitKey::ClientIp => context.client_ip.clone(),
        }
    }

    /// Reconfigure rate limiter
    pub fn reconfigure(&self, config: &RateLimitConfig) {
        *self.config.write() = config.clone();

        // Update global limiter
        let new_global = config.global.as_ref().map(create_limiter_pair);
        *self.global_limiter.write() = new_global;

        // Clear per-client limiters (they'll be recreated on demand)
        self.client_limiters.clear();
        self.topic_limiters.clear();
    }

    /// Clean up expired limiters (call periodically)
    pub fn cleanup(&self) {
        // Simple cleanup: remove limiters that haven't been used
        // In production, you'd track last access time
        if self.client_limiters.len() > 10000 {
            self.client_limiters.clear();
        }
        if self.topic_limiters.len() > 1000 {
            self.topic_limiters.clear();
        }
    }

    /// Get current client count (for metrics)
    pub fn client_count(&self) -> usize {
        self.client_limiters.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(&RateLimitConfig::default())
    }
}

fn create_limiter_pair(limit: &RateLimit) -> ClientLimiter {
    let messages = if limit.messages_per_second > 0 {
        let quota = Quota::per_second(
            NonZeroU32::new(limit.messages_per_second).unwrap_or(nonzero!(1u32))
        ).allow_burst(
            NonZeroU32::new(limit.burst).unwrap_or(nonzero!(1u32))
        );
        Some(Arc::new(GovRateLimiter::direct(quota)))
    } else {
        None
    };

    let bytes = if limit.bytes_per_second > 0 {
        // For bytes, use cells_per_second
        let quota = Quota::per_second(
            NonZeroU32::new(limit.bytes_per_second.min(u32::MAX as u64) as u32).unwrap_or(nonzero!(1u32))
        ).allow_burst(
            NonZeroU32::new(limit.burst * 1024).unwrap_or(nonzero!(1024u32))
        );
        Some(Arc::new(GovRateLimiter::direct(quota)))
    } else {
        None
    };

    ClientLimiter { messages, bytes }
}

fn check_limiter(limiter: &ClientLimiter, payload_size: usize) -> bool {
    // Check message count
    if let Some(ref msg_limiter) = limiter.messages {
        if msg_limiter.check().is_err() {
            return false;
        }
    }

    // Check byte count
    if let Some(ref byte_limiter) = limiter.bytes {
        let cells = NonZeroU32::new(payload_size.max(1) as u32).unwrap_or(nonzero!(1u32));
        if byte_limiter.check_n(cells).is_err() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context(client_id: &str) -> ConnectionContext {
        ConnectionContext {
            client_id: client_id.to_string(),
            username: None,
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 4,
            groups: vec![],
            attributes: Default::default(),
        }
    }

    #[test]
    fn test_disabled_rate_limiting() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(&config);
        let context = make_context("client1");

        // Should always allow when disabled
        for _ in 0..1000 {
            let result = limiter.check_message(&context, "test/topic", 1000);
            assert!(result.allowed);
        }
    }

    #[test]
    fn test_per_client_rate_limit() {
        let config = RateLimitConfig {
            enabled: true,
            per_client: Some(RateLimit {
                messages_per_second: 2,
                bytes_per_second: 0,
                burst: 2,
            }),
            ..Default::default()
        };
        let limiter = RateLimiter::new(&config);
        let context = make_context("client1");

        // First few should succeed (burst)
        for _ in 0..2 {
            let result = limiter.check_message(&context, "test/topic", 100);
            assert!(result.allowed, "Should allow within burst");
        }

        // Next should fail
        let result = limiter.check_message(&context, "test/topic", 100);
        assert!(!result.allowed, "Should deny after burst exceeded");
        assert!(result.exceeded_limit.unwrap().starts_with("per-client:"));
    }

    #[test]
    fn test_different_clients() {
        let config = RateLimitConfig {
            enabled: true,
            per_client: Some(RateLimit {
                messages_per_second: 1,
                bytes_per_second: 0,
                burst: 1,
            }),
            ..Default::default()
        };
        let limiter = RateLimiter::new(&config);

        let context1 = make_context("client1");
        let context2 = make_context("client2");

        // Each client has independent limit
        assert!(limiter.check_message(&context1, "test", 100).allowed);
        assert!(limiter.check_message(&context2, "test", 100).allowed);

        // Both should now be rate limited
        assert!(!limiter.check_message(&context1, "test", 100).allowed);
        assert!(!limiter.check_message(&context2, "test", 100).allowed);
    }

    #[test]
    fn test_per_topic_rate_limit() {
        let config = RateLimitConfig {
            enabled: true,
            per_topic: vec![
                crate::config::TopicRateLimit {
                    topic: "high-freq/#".to_string(),
                    limit: RateLimit {
                        messages_per_second: 100,
                        bytes_per_second: 0,
                        burst: 10,
                    },
                },
                crate::config::TopicRateLimit {
                    topic: "low-freq/#".to_string(),
                    limit: RateLimit {
                        messages_per_second: 1,
                        bytes_per_second: 0,
                        burst: 1,
                    },
                },
            ],
            ..Default::default()
        };
        let limiter = RateLimiter::new(&config);
        let context = make_context("client1");

        // High-freq topic allows many messages
        for _ in 0..10 {
            assert!(limiter.check_message(&context, "high-freq/data", 100).allowed);
        }

        // Low-freq topic is more restrictive
        assert!(limiter.check_message(&context, "low-freq/data", 100).allowed);
        assert!(!limiter.check_message(&context, "low-freq/data", 100).allowed);
    }
}
