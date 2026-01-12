//! Retained message control module

use crate::config::RetainedConfig;
use crate::mqtt::TopicMatcher;
use parking_lot::RwLock;
use std::sync::Arc;

/// Retained message check result
#[derive(Debug, Clone)]
pub struct RetainedCheckResult {
    /// Whether retained is allowed
    pub allowed: bool,
    /// Reason for denial
    pub reason: Option<String>,
}

impl RetainedCheckResult {
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    pub fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.to_string()),
        }
    }
}

/// Retained message controller
pub struct RetainedController {
    config: Arc<RwLock<RetainedConfig>>,
    topic_matcher: TopicMatcher,
}

impl RetainedController {
    pub fn new(config: &RetainedConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            topic_matcher: TopicMatcher::new(),
        }
    }

    /// Check if a retained message is allowed
    pub fn check(&self, topic: &str, payload_size: usize, retain: bool) -> RetainedCheckResult {
        // If not a retained message, always allow
        if !retain {
            return RetainedCheckResult::allowed();
        }

        let config = self.config.read();

        // If control is disabled, allow everything
        if !config.enabled {
            return RetainedCheckResult::allowed();
        }

        // Check global setting
        if !config.allow_retained {
            // Check if topic is in allowed list
            let in_allowed = config.allowed_topics.iter()
                .any(|p| self.topic_matcher.matches(topic, p));

            if !in_allowed {
                return RetainedCheckResult::denied("Retained messages not allowed for this topic");
            }
        }

        // Check blocked list
        let in_blocked = config.blocked_topics.iter()
            .any(|p| self.topic_matcher.matches(topic, p));

        if in_blocked {
            return RetainedCheckResult::denied("Topic is in blocked list for retained messages");
        }

        // Check size limit
        if let Some(max_size) = config.max_size {
            if payload_size > max_size {
                return RetainedCheckResult::denied(&format!(
                    "Retained message size {} exceeds limit {}",
                    payload_size, max_size
                ));
            }
        }

        RetainedCheckResult::allowed()
    }

    /// Reconfigure
    pub fn reconfigure(&self, config: &RetainedConfig) {
        *self.config.write() = config.clone();
    }
}

impl Default for RetainedController {
    fn default() -> Self {
        Self::new(&RetainedConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_retained_always_allowed() {
        let config = RetainedConfig {
            enabled: true,
            allow_retained: false,
            ..Default::default()
        };
        let controller = RetainedController::new(&config);

        let result = controller.check("any/topic", 1000, false);
        assert!(result.allowed);
    }

    #[test]
    fn test_disabled_allows_all() {
        let config = RetainedConfig {
            enabled: false,
            allow_retained: false,
            ..Default::default()
        };
        let controller = RetainedController::new(&config);

        let result = controller.check("any/topic", 1000, true);
        assert!(result.allowed);
    }

    #[test]
    fn test_global_deny_with_allowed_topics() {
        let config = RetainedConfig {
            enabled: true,
            allow_retained: false,
            allowed_topics: vec!["config/#".to_string()],
            ..Default::default()
        };
        let controller = RetainedController::new(&config);

        // Config topics allowed
        let result = controller.check("config/device1", 100, true);
        assert!(result.allowed);

        // Other topics denied
        let result = controller.check("data/sensor1", 100, true);
        assert!(!result.allowed);
    }

    #[test]
    fn test_blocked_topics() {
        let config = RetainedConfig {
            enabled: true,
            allow_retained: true,
            blocked_topics: vec!["temp/#".to_string()],
            ..Default::default()
        };
        let controller = RetainedController::new(&config);

        // Blocked topic
        let result = controller.check("temp/sensor1", 100, true);
        assert!(!result.allowed);

        // Other topics allowed
        let result = controller.check("status/device1", 100, true);
        assert!(result.allowed);
    }

    #[test]
    fn test_size_limit() {
        let config = RetainedConfig {
            enabled: true,
            allow_retained: true,
            max_size: Some(1000),
            ..Default::default()
        };
        let controller = RetainedController::new(&config);

        // Under limit
        let result = controller.check("any/topic", 500, true);
        assert!(result.allowed);

        // Over limit
        let result = controller.check("any/topic", 2000, true);
        assert!(!result.allowed);
    }
}
