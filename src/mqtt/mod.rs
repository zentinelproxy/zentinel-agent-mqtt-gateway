//! MQTT protocol handling module
//!
//! Provides MQTT packet parsing and topic matching for the gateway agent.

mod parser;
mod topic;

pub use parser::{parse_packet, MqttPacket, MqttPacketType, ParsedConnect, ParsedPublish, ParsedSubscribe, ParsedUnsubscribe};
pub use topic::TopicMatcher;
