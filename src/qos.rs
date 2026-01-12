//! QoS enforcement module

use crate::config::QosConfig;
use crate::mqtt::TopicMatcher;
use parking_lot::RwLock;
use std::sync::Arc;

/// QoS check result
#[derive(Debug, Clone)]
pub struct QosCheckResult {
    /// Whether the QoS is allowed
    pub allowed: bool,
    /// Recommended QoS (if downgrade is enabled)
    pub recommended_qos: u8,
    /// Reason for any changes
    pub reason: Option<String>,
}

impl QosCheckResult {
    pub fn allowed(qos: u8) -> Self {
        Self {
            allowed: true,
            recommended_qos: qos,
            reason: None,
        }
    }

    pub fn downgraded(original: u8, new: u8) -> Self {
        Self {
            allowed: true,
            recommended_qos: new,
            reason: Some(format!("QoS downgraded from {} to {}", original, new)),
        }
    }

    pub fn denied(qos: u8, max: u8) -> Self {
        Self {
            allowed: false,
            recommended_qos: max,
            reason: Some(format!("QoS {} exceeds maximum {}", qos, max)),
        }
    }
}

/// QoS enforcer
pub struct QosEnforcer {
    config: Arc<RwLock<QosConfig>>,
    topic_matcher: TopicMatcher,
}

impl QosEnforcer {
    pub fn new(config: &QosConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            topic_matcher: TopicMatcher::new(),
        }
    }

    /// Check if QoS is allowed for a topic
    pub fn check(&self, topic: &str, qos: u8) -> QosCheckResult {
        let config = self.config.read();

        if !config.enabled {
            return QosCheckResult::allowed(qos);
        }

        // Find per-topic limit
        let max_qos = config.per_topic
            .iter()
            .find(|limit| self.topic_matcher.matches(topic, &limit.topic))
            .map(|limit| limit.max_qos)
            .unwrap_or(config.max_qos);

        if qos <= max_qos {
            QosCheckResult::allowed(qos)
        } else if config.downgrade {
            QosCheckResult::downgraded(qos, max_qos)
        } else {
            QosCheckResult::denied(qos, max_qos)
        }
    }

    /// Reconfigure
    pub fn reconfigure(&self, config: &QosConfig) {
        *self.config.write() = config.clone();
    }
}

impl Default for QosEnforcer {
    fn default() -> Self {
        Self::new(&QosConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TopicQosLimit;

    #[test]
    fn test_allowed_qos() {
        let config = QosConfig {
            enabled: true,
            max_qos: 2,
            downgrade: false,
            per_topic: vec![],
        };
        let enforcer = QosEnforcer::new(&config);

        let result = enforcer.check("test/topic", 1);
        assert!(result.allowed);
        assert_eq!(result.recommended_qos, 1);
    }

    #[test]
    fn test_qos_downgrade() {
        let config = QosConfig {
            enabled: true,
            max_qos: 1,
            downgrade: true,
            per_topic: vec![],
        };
        let enforcer = QosEnforcer::new(&config);

        let result = enforcer.check("test/topic", 2);
        assert!(result.allowed);
        assert_eq!(result.recommended_qos, 1);
        assert!(result.reason.is_some());
    }

    #[test]
    fn test_qos_denied() {
        let config = QosConfig {
            enabled: true,
            max_qos: 1,
            downgrade: false,
            per_topic: vec![],
        };
        let enforcer = QosEnforcer::new(&config);

        let result = enforcer.check("test/topic", 2);
        assert!(!result.allowed);
    }

    #[test]
    fn test_per_topic_limit() {
        let config = QosConfig {
            enabled: true,
            max_qos: 2,
            downgrade: true,
            per_topic: vec![
                TopicQosLimit {
                    topic: "realtime/#".to_string(),
                    max_qos: 0,
                },
            ],
        };
        let enforcer = QosEnforcer::new(&config);

        // realtime topic should be limited to QoS 0
        let result = enforcer.check("realtime/data", 2);
        assert!(result.allowed);
        assert_eq!(result.recommended_qos, 0);

        // other topics use global limit
        let result = enforcer.check("normal/data", 2);
        assert!(result.allowed);
        assert_eq!(result.recommended_qos, 2);
    }

    #[test]
    fn test_disabled() {
        let config = QosConfig {
            enabled: false,
            ..Default::default()
        };
        let enforcer = QosEnforcer::new(&config);

        let result = enforcer.check("test/topic", 2);
        assert!(result.allowed);
        assert_eq!(result.recommended_qos, 2);
    }
}
