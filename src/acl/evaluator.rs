//! ACL rule evaluation engine

use crate::config::{AclAction, AclConfig, AclRule};
use crate::mqtt::TopicMatcher;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, warn};

use super::rules::{AclDecision, AclRequest, CompiledRule};

/// ACL Evaluator - evaluates access control rules for MQTT operations
pub struct AclEvaluator {
    /// Compiled rules sorted by priority (highest first)
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    /// Default action when no rule matches
    default_action: Arc<RwLock<AclAction>>,
    /// Topic matcher for wildcard patterns
    topic_matcher: TopicMatcher,
    /// Whether ACL is enabled
    enabled: Arc<RwLock<bool>>,
}

impl AclEvaluator {
    /// Create a new ACL evaluator from configuration
    pub fn new(config: &AclConfig) -> Result<Self, String> {
        let mut rules = Vec::new();

        for rule in &config.rules {
            match CompiledRule::from_config(rule) {
                Ok(compiled) => rules.push(compiled),
                Err(e) => {
                    warn!(rule = %rule.name, error = %e, "Failed to compile ACL rule");
                    return Err(format!("Failed to compile rule '{}': {}", rule.name, e));
                }
            }
        }

        // Sort by priority (highest first)
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            default_action: Arc::new(RwLock::new(config.default_action)),
            topic_matcher: TopicMatcher::new(),
            enabled: Arc::new(RwLock::new(config.enabled)),
        })
    }

    /// Update rules from new configuration
    pub fn reconfigure(&self, config: &AclConfig) -> Result<(), String> {
        let mut new_rules = Vec::new();

        for rule in &config.rules {
            match CompiledRule::from_config(rule) {
                Ok(compiled) => new_rules.push(compiled),
                Err(e) => {
                    return Err(format!("Failed to compile rule '{}': {}", rule.name, e));
                }
            }
        }

        // Sort by priority (highest first)
        new_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        *self.rules.write() = new_rules;
        *self.default_action.write() = config.default_action;
        *self.enabled.write() = config.enabled;

        Ok(())
    }

    /// Add rules from an external source (e.g., rules file)
    pub fn add_rules(&self, rules: &[AclRule]) -> Result<(), String> {
        let mut current = self.rules.write();

        for rule in rules {
            match CompiledRule::from_config(rule) {
                Ok(compiled) => current.push(compiled),
                Err(e) => {
                    return Err(format!("Failed to compile rule '{}': {}", rule.name, e));
                }
            }
        }

        // Re-sort by priority
        current.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(())
    }

    /// Evaluate an ACL request
    pub fn evaluate(&self, request: &AclRequest<'_>) -> AclDecision {
        // If ACL is disabled, allow everything
        if !*self.enabled.read() {
            return AclDecision {
                allowed: true,
                rule_name: None,
                max_qos: None,
                reason: "ACL disabled".to_string(),
            };
        }

        let rules = self.rules.read();

        for rule in rules.iter() {
            // Check if rule matches context (username, client_id, ip, etc.)
            if !rule.matches_context(request.context) {
                continue;
            }

            // Check if rule matches action
            if !rule.matches_action(request.action) {
                continue;
            }

            // Check if any topic pattern matches
            let topic_matches = rule.topic_patterns.iter().any(|pattern| {
                self.topic_matcher.matches(request.topic, pattern)
            });

            if !topic_matches {
                continue;
            }

            // Rule matches!
            debug!(
                rule = %rule.name,
                topic = %request.topic,
                action = ?request.action,
                decision = ?rule.decision,
                "ACL rule matched"
            );

            return match rule.decision {
                AclAction::Allow => AclDecision::allow(&rule.name, rule.max_qos),
                AclAction::Deny => AclDecision::deny(&rule.name),
            };
        }

        // No rule matched, use default action
        let default = *self.default_action.read();
        debug!(
            topic = %request.topic,
            action = ?request.action,
            default = ?default,
            "No ACL rule matched, using default"
        );

        match default {
            AclAction::Allow => AclDecision::default_allow(),
            AclAction::Deny => AclDecision::default_deny(),
        }
    }

    /// Check if a topic can be published to
    pub fn can_publish(
        &self,
        context: &crate::config::ConnectionContext,
        topic: &str,
        qos: u8,
    ) -> AclDecision {
        self.evaluate(&AclRequest {
            context,
            topic,
            action: crate::config::MqttAction::Publish,
            qos: Some(qos),
        })
    }

    /// Check if a topic filter can be subscribed to
    pub fn can_subscribe(
        &self,
        context: &crate::config::ConnectionContext,
        topic_filter: &str,
        qos: u8,
    ) -> AclDecision {
        self.evaluate(&AclRequest {
            context,
            topic: topic_filter,
            action: crate::config::MqttAction::Subscribe,
            qos: Some(qos),
        })
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }
}

impl Default for AclEvaluator {
    fn default() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            default_action: Arc::new(RwLock::new(AclAction::Deny)),
            topic_matcher: TopicMatcher::new(),
            enabled: Arc::new(RwLock::new(true)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AclMatch, ConnectionContext, MqttAction};

    fn make_config(rules: Vec<AclRule>) -> AclConfig {
        AclConfig {
            enabled: true,
            default_action: AclAction::Deny,
            rules,
            rules_file: None,
            cache_decisions: false,
        }
    }

    fn make_context(client_id: &str, username: Option<&str>) -> ConnectionContext {
        ConnectionContext {
            client_id: client_id.to_string(),
            username: username.map(|s| s.to_string()),
            client_ip: "192.168.1.1".to_string(),
            protocol_version: 4,
            groups: vec![],
            attributes: Default::default(),
        }
    }

    #[test]
    fn test_basic_allow_rule() {
        let config = make_config(vec![AclRule {
            name: "allow-sensors".to_string(),
            match_conditions: AclMatch {
                username_regex: Some("^sensor-.*".to_string()),
                ..Default::default()
            },
            topics: vec!["sensors/#".to_string()],
            actions: vec![MqttAction::Publish],
            decision: AclAction::Allow,
            max_qos: Some(1),
            priority: 0,
        }]);

        let evaluator = AclEvaluator::new(&config).unwrap();
        let context = make_context("sensor-001", Some("sensor-001"));

        let decision = evaluator.can_publish(&context, "sensors/temp/living-room", 1);
        assert!(decision.allowed);
        assert_eq!(decision.max_qos, Some(1));
    }

    #[test]
    fn test_default_deny() {
        let config = make_config(vec![]);
        let evaluator = AclEvaluator::new(&config).unwrap();
        let context = make_context("client1", Some("user1"));

        let decision = evaluator.can_publish(&context, "some/topic", 0);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "No matching rule, default deny");
    }

    #[test]
    fn test_priority_ordering() {
        let config = make_config(vec![
            AclRule {
                name: "low-priority-allow".to_string(),
                match_conditions: Default::default(),
                topics: vec!["#".to_string()],
                actions: vec![],
                decision: AclAction::Allow,
                max_qos: None,
                priority: 0,
            },
            AclRule {
                name: "high-priority-deny".to_string(),
                match_conditions: Default::default(),
                topics: vec!["admin/#".to_string()],
                actions: vec![],
                decision: AclAction::Deny,
                max_qos: None,
                priority: 10,
            },
        ]);

        let evaluator = AclEvaluator::new(&config).unwrap();
        let context = make_context("client1", None);

        // admin topic should be denied (high priority rule)
        let decision = evaluator.can_publish(&context, "admin/settings", 0);
        assert!(!decision.allowed);
        assert_eq!(decision.rule_name, Some("high-priority-deny".to_string()));

        // other topics should be allowed (low priority rule)
        let decision = evaluator.can_publish(&context, "public/data", 0);
        assert!(decision.allowed);
    }

    #[test]
    fn test_topic_wildcard_matching() {
        let config = make_config(vec![AclRule {
            name: "allow-user-topics".to_string(),
            match_conditions: Default::default(),
            topics: vec!["users/+/messages".to_string()],
            actions: vec![],
            decision: AclAction::Allow,
            max_qos: None,
            priority: 0,
        }]);

        let evaluator = AclEvaluator::new(&config).unwrap();
        let context = make_context("client1", None);

        // Should match
        assert!(evaluator.can_publish(&context, "users/alice/messages", 0).allowed);
        assert!(evaluator.can_publish(&context, "users/bob/messages", 0).allowed);

        // Should not match
        assert!(!evaluator.can_publish(&context, "users/alice/private", 0).allowed);
        assert!(!evaluator.can_publish(&context, "users/messages", 0).allowed);
    }

    #[test]
    fn test_disabled_acl() {
        let mut config = make_config(vec![]);
        config.enabled = false;

        let evaluator = AclEvaluator::new(&config).unwrap();
        let context = make_context("client1", None);

        // Everything should be allowed when ACL is disabled
        let decision = evaluator.can_publish(&context, "any/topic", 0);
        assert!(decision.allowed);
        assert_eq!(decision.reason, "ACL disabled");
    }
}
