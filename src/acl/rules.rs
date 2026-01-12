//! ACL rule types and matching logic

use crate::config::{AclAction, AclRule, ConnectionContext, MqttAction};
use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

/// ACL evaluation request
#[derive(Debug, Clone)]
pub struct AclRequest<'a> {
    /// Connection context (client_id, username, ip, etc.)
    pub context: &'a ConnectionContext,
    /// Topic being accessed
    pub topic: &'a str,
    /// Action being performed
    pub action: MqttAction,
    /// Requested QoS level (for publish/subscribe)
    pub qos: Option<u8>,
}

/// Result of ACL evaluation
#[derive(Debug, Clone)]
pub struct AclDecision {
    /// Whether access is allowed
    pub allowed: bool,
    /// Name of the matching rule (if any)
    pub rule_name: Option<String>,
    /// Maximum allowed QoS (if rule specifies one)
    pub max_qos: Option<u8>,
    /// Reason for the decision
    pub reason: String,
}

impl AclDecision {
    pub fn allow(rule_name: &str, max_qos: Option<u8>) -> Self {
        Self {
            allowed: true,
            rule_name: Some(rule_name.to_string()),
            max_qos,
            reason: format!("Allowed by rule: {}", rule_name),
        }
    }

    pub fn deny(rule_name: &str) -> Self {
        Self {
            allowed: false,
            rule_name: Some(rule_name.to_string()),
            max_qos: None,
            reason: format!("Denied by rule: {}", rule_name),
        }
    }

    pub fn default_deny() -> Self {
        Self {
            allowed: false,
            rule_name: None,
            max_qos: None,
            reason: "No matching rule, default deny".to_string(),
        }
    }

    pub fn default_allow() -> Self {
        Self {
            allowed: true,
            rule_name: None,
            max_qos: None,
            reason: "No matching rule, default allow".to_string(),
        }
    }
}

/// Compiled ACL rule for efficient matching
#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub priority: i32,
    pub username_regex: Option<Regex>,
    pub client_id_regex: Option<Regex>,
    pub client_ip_net: Option<IpNet>,
    pub groups: Option<Vec<String>>,
    pub protocol_version: Option<u8>,
    pub topic_patterns: Vec<String>,
    pub actions: Vec<MqttAction>,
    pub decision: AclAction,
    pub max_qos: Option<u8>,
}

impl CompiledRule {
    /// Compile a rule from configuration
    pub fn from_config(rule: &AclRule) -> Result<Self, String> {
        let username_regex = match (&rule.match_conditions.username, &rule.match_conditions.username_regex) {
            (Some(exact), _) => Some(Regex::new(&format!("^{}$", regex::escape(exact)))
                .map_err(|e| format!("Invalid username pattern: {}", e))?),
            (_, Some(pattern)) => Some(Regex::new(pattern)
                .map_err(|e| format!("Invalid username regex: {}", e))?),
            (None, None) => None,
        };

        let client_id_regex = match (&rule.match_conditions.client_id, &rule.match_conditions.client_id_regex) {
            (Some(exact), _) => Some(Regex::new(&format!("^{}$", regex::escape(exact)))
                .map_err(|e| format!("Invalid client_id pattern: {}", e))?),
            (_, Some(pattern)) => Some(Regex::new(pattern)
                .map_err(|e| format!("Invalid client_id regex: {}", e))?),
            (None, None) => None,
        };

        let client_ip_net = rule.match_conditions.client_ip
            .as_ref()
            .map(|ip| IpNet::from_str(ip).or_else(|_| {
                // Try parsing as single IP
                IpAddr::from_str(ip)
                    .map(|addr| match addr {
                        IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).unwrap()),
                        IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).unwrap()),
                    })
                    .map_err(|e| format!("Invalid IP/CIDR: {}", e))
            }))
            .transpose()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            name: rule.name.clone(),
            priority: rule.priority,
            username_regex,
            client_id_regex,
            client_ip_net,
            groups: rule.match_conditions.groups.clone(),
            protocol_version: rule.match_conditions.protocol_version,
            topic_patterns: rule.topics.clone(),
            actions: rule.actions.clone(),
            decision: rule.decision,
            max_qos: rule.max_qos,
        })
    }

    /// Check if this rule matches the request context
    pub fn matches_context(&self, context: &ConnectionContext) -> bool {
        // Check username
        if let Some(ref regex) = self.username_regex {
            match &context.username {
                Some(username) => {
                    if !regex.is_match(username) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // Check client ID
        if let Some(ref regex) = self.client_id_regex {
            if !regex.is_match(&context.client_id) {
                return false;
            }
        }

        // Check client IP
        if let Some(ref net) = self.client_ip_net {
            match IpAddr::from_str(&context.client_ip) {
                Ok(addr) => {
                    if !net.contains(&addr) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }

        // Check groups
        if let Some(ref required_groups) = self.groups {
            let has_group = required_groups.iter().any(|g| context.groups.contains(g));
            if !has_group {
                return false;
            }
        }

        // Check protocol version
        if let Some(version) = self.protocol_version {
            if context.protocol_version != version {
                return false;
            }
        }

        true
    }

    /// Check if this rule matches the action
    pub fn matches_action(&self, action: MqttAction) -> bool {
        self.actions.is_empty() || self.actions.contains(&action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AclAction, AclMatch};

    fn make_context(client_id: &str, username: Option<&str>, ip: &str) -> ConnectionContext {
        ConnectionContext {
            client_id: client_id.to_string(),
            username: username.map(|s| s.to_string()),
            client_ip: ip.to_string(),
            protocol_version: 4,
            groups: vec![],
            attributes: Default::default(),
        }
    }

    #[test]
    fn test_username_matching() {
        let rule = AclRule {
            name: "test".to_string(),
            match_conditions: AclMatch {
                username_regex: Some("^sensor-.*".to_string()),
                ..Default::default()
            },
            topics: vec!["sensors/#".to_string()],
            actions: vec![],
            decision: AclAction::Allow,
            max_qos: None,
            priority: 0,
        };

        let compiled = CompiledRule::from_config(&rule).unwrap();

        let ctx1 = make_context("client1", Some("sensor-001"), "192.168.1.1");
        assert!(compiled.matches_context(&ctx1));

        let ctx2 = make_context("client1", Some("user-001"), "192.168.1.1");
        assert!(!compiled.matches_context(&ctx2));

        let ctx3 = make_context("client1", None, "192.168.1.1");
        assert!(!compiled.matches_context(&ctx3));
    }

    #[test]
    fn test_ip_cidr_matching() {
        let rule = AclRule {
            name: "test".to_string(),
            match_conditions: AclMatch {
                client_ip: Some("192.168.1.0/24".to_string()),
                ..Default::default()
            },
            topics: vec!["#".to_string()],
            actions: vec![],
            decision: AclAction::Allow,
            max_qos: None,
            priority: 0,
        };

        let compiled = CompiledRule::from_config(&rule).unwrap();

        let ctx1 = make_context("client1", None, "192.168.1.100");
        assert!(compiled.matches_context(&ctx1));

        let ctx2 = make_context("client1", None, "192.168.2.1");
        assert!(!compiled.matches_context(&ctx2));
    }

    #[test]
    fn test_action_matching() {
        let rule = AclRule {
            name: "test".to_string(),
            match_conditions: Default::default(),
            topics: vec!["#".to_string()],
            actions: vec![MqttAction::Publish],
            decision: AclAction::Allow,
            max_qos: None,
            priority: 0,
        };

        let compiled = CompiledRule::from_config(&rule).unwrap();

        assert!(compiled.matches_action(MqttAction::Publish));
        assert!(!compiled.matches_action(MqttAction::Subscribe));
    }

    #[test]
    fn test_empty_actions_matches_all() {
        let rule = AclRule {
            name: "test".to_string(),
            match_conditions: Default::default(),
            topics: vec!["#".to_string()],
            actions: vec![],
            decision: AclAction::Allow,
            max_qos: None,
            priority: 0,
        };

        let compiled = CompiledRule::from_config(&rule).unwrap();

        assert!(compiled.matches_action(MqttAction::Publish));
        assert!(compiled.matches_action(MqttAction::Subscribe));
        assert!(compiled.matches_action(MqttAction::Unsubscribe));
    }
}
