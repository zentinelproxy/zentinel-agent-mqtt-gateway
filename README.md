# zentinel-agent-mqtt-gateway

IoT protocol security agent for [Zentinel](https://github.com/zentinelproxy/zentinel) reverse proxy. Provides topic-based ACLs, client authentication, payload inspection, rate limiting, and QoS enforcement for MQTT traffic.

> **Transport:** This agent processes MQTT packets carried over WebSocket frames. Native MQTT (TCP port 1883/8883) is not supported — MQTT clients must connect via WebSocket.

## Features

- **Topic-Based ACLs** — Allow/deny publish/subscribe per topic with `+` and `#` wildcards
- **Client Authentication** — Username/password (bcrypt), JWT tokens
- **Payload Inspection** — SQLi, command injection, XSS detection + JSON schema validation
- **Rate Limiting** — Per-client and per-topic message rate limits (token bucket)
- **QoS Enforcement** — Maximum QoS levels with automatic downgrade
- **Retained Message Control** — Allow/deny retained flag per topic

## Installation

### Using Cargo

```bash
cargo install zentinel-agent-mqtt-gateway
```

### From Source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway
cd zentinel-agent-mqtt-gateway
cargo build --release
```

## Quick Start

```bash
# Run with defaults
zentinel-mqtt-gateway-agent --socket /tmp/zentinel-mqtt.sock

# With configuration file
zentinel-mqtt-gateway-agent \
  --socket /tmp/zentinel-mqtt.sock \
  --config /etc/zentinel/mqtt-gateway.json

# With JSON logging
zentinel-mqtt-gateway-agent \
  --socket /tmp/zentinel-mqtt.sock \
  --json-logs \
  --log-level debug
```

## CLI Options

| Option | Env Var | Description | Default |
|--------|---------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/zentinel-mqtt-gateway-agent.sock` |
| `--grpc-address` | `AGENT_GRPC_ADDRESS` | gRPC listen address | - |
| `--config` | `MQTT_CONFIG` | Configuration file path | - |
| `--log-level` | `MQTT_LOG_LEVEL` | Log level (trace, debug, info, warn, error) | `info` |
| `--json-logs` | - | Enable JSON log format | `false` |

## Configuration

```json
{
  "auth": {
    "enabled": true,
    "allow-anonymous": false,
    "providers": [
      {
        "type": "file",
        "path": "/etc/zentinel/mqtt-users.json"
      }
    ]
  },
  "acl": {
    "enabled": true,
    "default-action": "deny",
    "rules": [
      {
        "name": "sensors-publish",
        "match": { "username-regex": "^sensor-" },
        "topics": ["sensors/+/data"],
        "actions": ["publish"],
        "decision": "allow",
        "max-qos": 1,
        "priority": 10
      },
      {
        "name": "operators-subscribe",
        "match": { "groups": ["operators"] },
        "topics": ["sensors/#"],
        "actions": ["subscribe"],
        "decision": "allow",
        "priority": 10
      },
      {
        "name": "block-internal",
        "topics": ["$SYS/#", "internal/#"],
        "decision": "deny",
        "priority": 100
      }
    ]
  },
  "inspection": {
    "enabled": true,
    "max-payload-size": 262144,
    "patterns": {
      "sqli": true,
      "command-injection": true
    }
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
  }
}
```

### ACL Precedence

Rules are evaluated by `priority` (highest value first). The first matching rule wins. If no rule matches, `default-action` applies. This is a strict first-match model — rules do not accumulate.

### Topic Wildcards

Standard MQTT wildcards:
- `+` — Matches exactly one level (`sensors/+/data` matches `sensors/temp/data`)
- `#` — Matches zero or more levels (`sensors/#` matches `sensors/temp/living/zone1`)

## Zentinel Configuration

```kdl
agents {
    agent "mqtt-gateway" {
        type "custom"
        unix-socket "/tmp/zentinel-mqtt.sock"
        events "websocket_frame"
        timeout-ms 100
        failure-mode "closed"
    }
}

routes {
    route "mqtt" {
        matches { path-prefix "/mqtt" }
        websocket enabled {
            max-frame-size 65536
        }
        agents "mqtt-gateway"
        upstream "mqtt-broker"
    }
}
```

## MQTT Packet Handling

| Packet | Checks Applied |
|--------|----------------|
| **CONNECT** | Authentication, client ID validation |
| **PUBLISH** | ACL, rate limit, QoS, retained, payload inspection |
| **SUBSCRIBE** | ACL per topic filter |
| **UNSUBSCRIBE** | ACL (optional) |
| **PINGREQ/PINGRESP** | Allowed (keep-alive) |
| **DISCONNECT** | Cleanup connection state |

## Decisions

| Decision | WebSocket Action | Use Case |
|----------|------------------|----------|
| **Allow** | Forward frame | Request passes all checks |
| **Drop** | Drop frame silently | Policy violation, rate limit |
| **Close** | Close connection (code 1008) | Auth failure, protocol error |

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock

# Run tests
cargo test

# Build release binary
cargo build --release
```

## License

Apache-2.0
