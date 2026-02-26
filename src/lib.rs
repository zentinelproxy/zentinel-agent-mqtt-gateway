//! MQTT Gateway Agent for Zentinel Proxy
//!
//! This agent provides comprehensive security controls for MQTT traffic:
//!
//! - **Authentication**: Username/password, JWT tokens, client certificates
//! - **Access Control**: Topic-based ACLs with wildcard support
//! - **Rate Limiting**: Per-client and per-topic message rate limits
//! - **Payload Inspection**: Malicious pattern detection, JSON schema validation
//! - **QoS Enforcement**: Maximum QoS levels with automatic downgrade
//! - **Retained Messages**: Control which topics can use retained messages
//!
//! # Architecture
//!
//! The agent processes MQTT packets from WebSocket binary frames. It implements
//! the Zentinel `AgentHandlerV2` trait and receives `WebSocketFrameEvent` for each
//! MQTT packet transmitted over WebSocket.
//!
//! # Example Configuration
//!
//! ```json
//! {
//!   "auth": {
//!     "enabled": true,
//!     "allow-anonymous": false,
//!     "providers": [
//!       { "type": "file", "path": "/etc/mqtt/users.json" }
//!     ]
//!   },
//!   "acl": {
//!     "enabled": true,
//!     "default-action": "deny",
//!     "rules": [
//!       {
//!         "name": "allow-sensors",
//!         "match": { "username-regex": "^sensor-" },
//!         "topics": ["sensors/+/data"],
//!         "actions": ["publish"],
//!         "decision": "allow"
//!       }
//!     ]
//!   }
//! }
//! ```

pub mod acl;
pub mod agent;
pub mod auth;
pub mod config;
pub mod inspection;
pub mod mqtt;
pub mod qos;
pub mod ratelimit;
pub mod retained;

// Re-export main types
pub use agent::MqttGatewayAgent;
pub use config::MqttGatewayConfig;
