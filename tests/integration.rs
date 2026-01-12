//! Integration tests for MQTT Gateway Agent

use sentinel_agent_mqtt_gateway::config::*;
use sentinel_agent_mqtt_gateway::mqtt::{parse_packet, MqttPacket, TopicMatcher};
use sentinel_agent_mqtt_gateway::acl::AclEvaluator;
use sentinel_agent_mqtt_gateway::MqttGatewayAgent;

/// Test MQTT packet parsing
#[test]
fn test_parse_connect_packet() {
    // MQTT CONNECT packet bytes (protocol 3.1.1)
    let connect_bytes = [
        0x10, 0x10, // Fixed header: CONNECT, remaining length 16
        0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol name "MQTT"
        0x04, // Protocol level (3.1.1)
        0x02, // Connect flags: clean session
        0x00, 0x3C, // Keep alive: 60 seconds
        0x00, 0x04, b't', b'e', b's', b't', // Client ID: "test"
    ];

    let packet = parse_packet(&connect_bytes).expect("Failed to parse CONNECT");
    match packet {
        MqttPacket::Connect(connect) => {
            assert_eq!(connect.client_id, "test");
            assert_eq!(connect.protocol_version, 4);
            assert!(connect.clean_session);
            assert_eq!(connect.keep_alive, 60);
            assert!(connect.username.is_none());
            assert!(connect.password.is_none());
        }
        _ => panic!("Expected CONNECT packet"),
    }
}

/// Test MQTT topic matching
#[test]
fn test_topic_matching() {
    let matcher = TopicMatcher::new();

    // Exact match
    assert!(matcher.matches("sensors/temp", "sensors/temp"));
    assert!(!matcher.matches("sensors/temp", "sensors/humidity"));

    // Single-level wildcard
    assert!(matcher.matches("sensors/temp", "sensors/+"));
    assert!(matcher.matches("sensors/temp/living", "+/temp/living"));
    assert!(!matcher.matches("sensors/temp/living", "sensors/+"));

    // Multi-level wildcard
    assert!(matcher.matches("sensors/temp/living/zone1", "sensors/#"));
    assert!(matcher.matches("sensors", "sensors/#"));
    assert!(matcher.matches("anything", "#"));
}

/// Test ACL evaluation
#[test]
fn test_acl_evaluation() {
    let config = AclConfig {
        enabled: true,
        default_action: AclAction::Deny,
        rules: vec![
            AclRule {
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
            },
            AclRule {
                name: "deny-admin".to_string(),
                match_conditions: Default::default(),
                topics: vec!["admin/#".to_string()],
                actions: vec![],
                decision: AclAction::Deny,
                max_qos: None,
                priority: 10,
            },
        ],
        rules_file: None,
        cache_decisions: false,
    };

    let evaluator = AclEvaluator::new(&config).unwrap();

    // Sensor user publishing to sensors topic
    let context = ConnectionContext {
        client_id: "sensor-001".to_string(),
        username: Some("sensor-001".to_string()),
        client_ip: "192.168.1.100".to_string(),
        protocol_version: 4,
        groups: vec![],
        attributes: Default::default(),
    };

    let result = evaluator.can_publish(&context, "sensors/temp/living", 1);
    assert!(result.allowed);
    assert_eq!(result.max_qos, Some(1));

    // Same user trying admin topic
    let result = evaluator.can_publish(&context, "admin/settings", 0);
    assert!(!result.allowed);

    // Unknown user (no match, default deny)
    let unknown_context = ConnectionContext {
        client_id: "unknown".to_string(),
        username: Some("unknown".to_string()),
        client_ip: "192.168.1.100".to_string(),
        protocol_version: 4,
        groups: vec![],
        attributes: Default::default(),
    };

    let result = evaluator.can_publish(&unknown_context, "public/data", 0);
    assert!(!result.allowed);
}

/// Test agent creation
#[test]
fn test_agent_creation() {
    let config = MqttGatewayConfig::default();
    let agent = MqttGatewayAgent::with_config(config);
    assert!(agent.is_ok());
}

/// Test configuration deserialization
#[test]
fn test_config_deserialization() {
    let json = r#"{
        "auth": {
            "enabled": true,
            "allow-anonymous": false,
            "min-client-id-length": 5,
            "max-client-id-length": 64
        },
        "acl": {
            "enabled": true,
            "default-action": "deny",
            "rules": [
                {
                    "name": "allow-all-publish",
                    "match": {},
                    "topics": ["public/#"],
                    "actions": ["publish", "subscribe"],
                    "decision": "allow"
                }
            ]
        },
        "rate-limit": {
            "enabled": true,
            "per-client": {
                "messages-per-second": 100,
                "bytes-per-second": 1048576,
                "burst": 50
            }
        },
        "qos": {
            "enabled": true,
            "max-qos": 1,
            "downgrade": true
        },
        "retained": {
            "enabled": true,
            "allow-retained": false,
            "allowed-topics": ["config/#"]
        },
        "general": {
            "block-mode": true,
            "log-packets": false
        }
    }"#;

    let config: MqttGatewayConfig = serde_json::from_str(json).expect("Failed to parse config");

    assert!(config.auth.enabled);
    assert!(!config.auth.allow_anonymous);
    assert_eq!(config.auth.min_client_id_length, 5);
    assert_eq!(config.auth.max_client_id_length, 64);

    assert!(config.acl.enabled);
    assert_eq!(config.acl.default_action, AclAction::Deny);
    assert_eq!(config.acl.rules.len(), 1);

    assert!(config.rate_limit.enabled);
    assert!(config.rate_limit.per_client.is_some());

    assert!(config.qos.enabled);
    assert_eq!(config.qos.max_qos, 1);
    assert!(config.qos.downgrade);

    assert!(config.retained.enabled);
    assert!(!config.retained.allow_retained);
}

/// Test inspection patterns
#[test]
fn test_inspection_patterns() {
    use sentinel_agent_mqtt_gateway::inspection::PatternInspector;

    let config = PatternConfig {
        sqli: true,
        command_injection: true,
        script_injection: true,
        path_traversal: true,
        custom_patterns: vec![],
    };

    let inspector = PatternInspector::new(&config).unwrap();
    assert!(inspector.pattern_count() > 0);

    // SQL injection
    let detections = inspector.inspect("SELECT * FROM users WHERE id=1 OR 1=1");
    assert!(!detections.is_empty());

    // Command injection
    let detections = inspector.inspect("; rm -rf /");
    assert!(!detections.is_empty());

    // XSS
    let detections = inspector.inspect("<script>alert('xss')</script>");
    assert!(!detections.is_empty());

    // Clean payload
    let detections = inspector.inspect(r#"{"temperature": 25.5, "humidity": 60}"#);
    assert!(detections.is_empty());
}

/// Test rate limiting
#[test]
fn test_rate_limiting() {
    use sentinel_agent_mqtt_gateway::ratelimit::RateLimiter;

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

    let context = ConnectionContext {
        client_id: "test-client".to_string(),
        username: None,
        client_ip: "127.0.0.1".to_string(),
        protocol_version: 4,
        groups: vec![],
        attributes: Default::default(),
    };

    // First two should succeed (burst)
    assert!(limiter.check_message(&context, "test/topic", 100).allowed);
    assert!(limiter.check_message(&context, "test/topic", 100).allowed);

    // Third should fail
    assert!(!limiter.check_message(&context, "test/topic", 100).allowed);
}

/// Test QoS enforcement
#[test]
fn test_qos_enforcement() {
    use sentinel_agent_mqtt_gateway::qos::QosEnforcer;

    let config = QosConfig {
        enabled: true,
        max_qos: 1,
        downgrade: true,
        per_topic: vec![
            TopicQosLimit {
                topic: "realtime/#".to_string(),
                max_qos: 0,
            },
        ],
    };

    let enforcer = QosEnforcer::new(&config);

    // Normal topic with QoS 2 -> downgraded to 1
    let result = enforcer.check("normal/topic", 2);
    assert!(result.allowed);
    assert_eq!(result.recommended_qos, 1);

    // Realtime topic with QoS 1 -> downgraded to 0
    let result = enforcer.check("realtime/data", 1);
    assert!(result.allowed);
    assert_eq!(result.recommended_qos, 0);
}

/// Test retained message control
#[test]
fn test_retained_control() {
    use sentinel_agent_mqtt_gateway::retained::RetainedController;

    let config = RetainedConfig {
        enabled: true,
        allow_retained: false,
        allowed_topics: vec!["config/#".to_string()],
        blocked_topics: vec![],
        max_size: Some(1000),
    };

    let controller = RetainedController::new(&config);

    // Non-retained always allowed
    assert!(controller.check("any/topic", 100, false).allowed);

    // Retained on allowed topic
    assert!(controller.check("config/device1", 100, true).allowed);

    // Retained on other topic
    assert!(!controller.check("data/sensor1", 100, true).allowed);

    // Retained too large
    assert!(!controller.check("config/large", 2000, true).allowed);
}
