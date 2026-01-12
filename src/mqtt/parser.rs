//! MQTT packet parsing
//!
//! Wraps the mqttrs crate to provide a higher-level interface for parsing
//! MQTT packets from WebSocket binary frames.

use anyhow::{Context, Result};
use mqttrs::{decode_slice, Packet, Protocol, QoS};

/// Parsed MQTT packet with extracted fields for security checks
#[derive(Debug, Clone)]
pub enum MqttPacket {
    Connect(ParsedConnect),
    Publish(ParsedPublish),
    Subscribe(ParsedSubscribe),
    Unsubscribe(ParsedUnsubscribe),
    PingReq,
    PingResp,
    Disconnect,
    Other(MqttPacketType),
}

/// MQTT packet type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
    Auth, // MQTT 5.0
}

impl MqttPacketType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
            Self::Auth => "AUTH",
        }
    }
}

/// Parsed CONNECT packet
#[derive(Debug, Clone)]
pub struct ParsedConnect {
    /// Protocol version (3 = 3.1, 4 = 3.1.1, 5 = 5.0)
    pub protocol_version: u8,
    /// Client identifier
    pub client_id: String,
    /// Clean session flag (v3.1.1) or clean start (v5.0)
    pub clean_session: bool,
    /// Keep alive interval in seconds
    pub keep_alive: u16,
    /// Username if provided
    pub username: Option<String>,
    /// Password if provided (stored as bytes for non-UTF8 passwords)
    pub password: Option<Vec<u8>>,
    /// Will topic if will message is set
    pub will_topic: Option<String>,
    /// Will message payload
    pub will_payload: Option<Vec<u8>>,
    /// Will QoS level
    pub will_qos: u8,
    /// Will retain flag
    pub will_retain: bool,
}

/// Parsed PUBLISH packet
#[derive(Debug, Clone)]
pub struct ParsedPublish {
    /// Topic name
    pub topic: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// QoS level (0, 1, or 2)
    pub qos: u8,
    /// Retain flag
    pub retain: bool,
    /// Duplicate delivery flag
    pub dup: bool,
    /// Packet identifier (for QoS > 0)
    pub packet_id: Option<u16>,
}

/// Parsed SUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct ParsedSubscribe {
    /// Packet identifier
    pub packet_id: u16,
    /// Topic filters with requested QoS
    pub subscriptions: Vec<Subscription>,
}

/// A single subscription in a SUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Topic filter (may contain + and # wildcards)
    pub topic_filter: String,
    /// Requested QoS level
    pub qos: u8,
}

/// Parsed UNSUBSCRIBE packet
#[derive(Debug, Clone)]
pub struct ParsedUnsubscribe {
    /// Packet identifier
    pub packet_id: u16,
    /// Topic filters to unsubscribe from
    pub topics: Vec<String>,
}

/// Parse an MQTT packet from raw bytes
pub fn parse_packet(data: &[u8]) -> Result<MqttPacket> {
    let packet = decode_slice(data)
        .context("Failed to decode MQTT packet")?
        .context("Incomplete MQTT packet")?;

    match packet {
        Packet::Connect(connect) => {
            let protocol_version = match connect.protocol {
                Protocol::MQTT311 => 4,
                Protocol::MQIsdp => 3,
            };

            Ok(MqttPacket::Connect(ParsedConnect {
                protocol_version,
                client_id: connect.client_id.to_string(),
                clean_session: connect.clean_session,
                keep_alive: connect.keep_alive,
                username: connect.username.map(|s| s.to_string()),
                password: connect.password.map(|p| p.to_vec()),
                will_topic: connect.last_will.as_ref().map(|w| w.topic.to_string()),
                will_payload: connect.last_will.as_ref().map(|w| w.message.to_vec()),
                will_qos: connect
                    .last_will
                    .as_ref()
                    .map(|w| qos_to_u8(w.qos))
                    .unwrap_or(0),
                will_retain: connect.last_will.as_ref().map(|w| w.retain).unwrap_or(false),
            }))
        }

        Packet::Publish(publish) => {
            // mqttrs uses QosPid enum to combine QoS and packet ID
            let (qos, packet_id) = match publish.qospid {
                mqttrs::QosPid::AtMostOnce => (0, None),
                mqttrs::QosPid::AtLeastOnce(pid) => (1, Some(pid.get())),
                mqttrs::QosPid::ExactlyOnce(pid) => (2, Some(pid.get())),
            };

            Ok(MqttPacket::Publish(ParsedPublish {
                topic: publish.topic_name.to_string(),
                payload: publish.payload.to_vec(),
                qos,
                retain: publish.retain,
                dup: publish.dup,
                packet_id,
            }))
        }

        Packet::Subscribe(subscribe) => {
            let subscriptions = subscribe
                .topics
                .iter()
                .map(|t| Subscription {
                    topic_filter: t.topic_path.to_string(),
                    qos: qos_to_u8(t.qos),
                })
                .collect();

            Ok(MqttPacket::Subscribe(ParsedSubscribe {
                packet_id: subscribe.pid.get(),
                subscriptions,
            }))
        }

        Packet::Unsubscribe(unsub) => Ok(MqttPacket::Unsubscribe(ParsedUnsubscribe {
            packet_id: unsub.pid.get(),
            topics: unsub.topics.iter().map(|t| t.to_string()).collect(),
        })),

        Packet::Pingreq => Ok(MqttPacket::PingReq),
        Packet::Pingresp => Ok(MqttPacket::PingResp),
        Packet::Disconnect => Ok(MqttPacket::Disconnect),

        Packet::Connack(_) => Ok(MqttPacket::Other(MqttPacketType::Connack)),
        Packet::Puback(_) => Ok(MqttPacket::Other(MqttPacketType::Puback)),
        Packet::Pubrec(_) => Ok(MqttPacket::Other(MqttPacketType::Pubrec)),
        Packet::Pubrel(_) => Ok(MqttPacket::Other(MqttPacketType::Pubrel)),
        Packet::Pubcomp(_) => Ok(MqttPacket::Other(MqttPacketType::Pubcomp)),
        Packet::Suback(_) => Ok(MqttPacket::Other(MqttPacketType::Suback)),
        Packet::Unsuback(_) => Ok(MqttPacket::Other(MqttPacketType::Unsuback)),
    }
}

fn qos_to_u8(qos: QoS) -> u8 {
    match qos {
        QoS::AtMostOnce => 0,
        QoS::AtLeastOnce => 1,
        QoS::ExactlyOnce => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_packet() {
        // MQTT CONNECT packet bytes (minimal)
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
            }
            _ => panic!("Expected CONNECT packet"),
        }
    }

    #[test]
    fn test_parse_publish_packet() {
        // MQTT PUBLISH packet bytes (QoS 0)
        // Remaining length = 2 (topic len) + 5 (topic) + 5 (payload) = 12 = 0x0C
        let publish_bytes = [
            0x30, 0x0C, // Fixed header: PUBLISH QoS 0, remaining length 12
            0x00, 0x05, b't', b'e', b's', b't', b'/', // Topic length + "test/"
            b'h', b'e', b'l', b'l', b'o', // Payload: "hello"
        ];

        let packet = parse_packet(&publish_bytes).expect("Failed to parse PUBLISH");
        match packet {
            MqttPacket::Publish(publish) => {
                assert_eq!(publish.topic, "test/");
                assert_eq!(publish.payload, b"hello");
                assert_eq!(publish.qos, 0);
                assert!(!publish.retain);
            }
            _ => panic!("Expected PUBLISH packet"),
        }
    }
}
