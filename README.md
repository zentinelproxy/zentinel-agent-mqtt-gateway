<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">MQTT gateway agent</h3>

<p align="center">Authenticates MQTT clients and enforces topic ACLs, rate limits, QoS and payload rules on MQTT packets carried in WebSocket frames.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/mqtt-gateway/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For IoT deployments that expose an MQTT broker over WebSocket behind Zentinel.
The agent parses each client-to-server binary frame as an MQTT packet: it
authenticates `CONNECT` (bcrypt user file or HS256 JWT), checks `PUBLISH`,
`SUBSCRIBE` and `UNSUBSCRIBE` against topic ACLs with `+` and `#` wildcards,
and applies per-client and per-topic rate limits, QoS and retained-message
rules and payload inspection to `PUBLISH`. A violation drops the frame; a
failed `CONNECT` closes the connection. Native MQTT over TCP (1883/8883) is not
handled, only MQTT over WebSocket.

## Quick start

```bash
zentinel bundle install mqtt-gateway
zentinel-mqtt-gateway-agent \
  --socket /var/run/zentinel/mqtt-gateway.sock \
  --config /etc/zentinel/mqtt-gateway.json
```

Without `--config` the ACL is on with `default-action "deny"` and no rules, so
every `PUBLISH`, `SUBSCRIBE` and `UNSUBSCRIBE` is dropped. Start from the
example under [Configuration](#configuration).

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "mqtt-gateway" type="custom" {
        unix-socket "/var/run/zentinel/mqtt-gateway.sock"
        events "websocket_frame"
        timeout-ms 100
        failure-mode "closed"
    }
}

routes {
    route "mqtt" {
        matches {
            path-prefix "/mqtt"
        }
        websocket #true
        websocket-inspection #true
        upstream "mqtt-broker"
    }
}

upstreams {
    upstream "mqtt-broker" {
        target "127.0.0.1:9001"
    }
}
```

Frames reach the agent because the route sets both `websocket #true` and
`websocket-inspection #true`, and the agent subscribes to `websocket_frame`; no
filter is involved. For frames, the agent block's `failure-mode` decides what
happens when the agent is unavailable. The proxy skips frame inspection when
the connection negotiates `permessage-deflate`.

## Install

**Bundle (recommended).** Downloads the release binary for your platform:

```bash
zentinel bundle install mqtt-gateway
```

See [the bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

**Cargo, from the repository.** The crate is not on crates.io; this builds the
`zentinel-mqtt-gateway-agent` binary from `main` (Rust 1.94.1 or newer):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway
```

**Release binaries.** Each [release](https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway/releases)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` archives:

```bash
VERSION=0.4.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-mqtt-gateway-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway/releases/download/v${VERSION}/zentinel-mqtt-gateway-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-mqtt-gateway-agent.tar.gz
sudo install -m 0755 zentinel-mqtt-gateway-agent /usr/local/bin/
```

**From source.**

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway
cd zentinel-agent-mqtt-gateway
cargo build --release
```

## Configuration

Command-line flags (none read environment variables):

| Flag | Default | Meaning |
|---|---|---|
| `-s, --socket <PATH>` | `/tmp/zentinel-mqtt-agent.sock` | Unix socket to listen on |
| `--grpc-address <ADDR>` | none | Serve gRPC on this address instead of the socket |
| `-c, --config <PATH>` | built-in defaults | JSON configuration file |
| `--log-level <LEVEL>` | `info` | Log level; `RUST_LOG` takes precedence |
| `--json-logs` | off | Log as JSON |

The agent reads its settings from the JSON file and, from the Zentinel
release that includes zentinelproxy/zentinel#603, from the agent block's
`config { }` in the proxy's KDL, which uses the same keys. Top-level keys and
their fields are kebab-case; fields inside an auth `providers` entry are
snake_case. A list may be given as a single value (`allowed-topics "config/#"`
in KDL arrives as one string).

The proxy sends the `config { }` block on every connection it opens to the
agent (each pooled connection at startup and every reconnect). The agent
applies both the file and the block under one rule:

- **Idempotent.** A block identical to the one already accepted (same
  canonical hash, key order ignored), or one that changes no setting, does
  nothing. When settings change, only the affected components are rebuilt:
  rate-limit buckets are kept unless their own limit changed, and
  authenticated connections are never dropped by a configure.
- **Merge, don't replace.** The block overlays the running configuration
  (the file, or the built-in defaults): objects merge key by key, a key that
  is absent keeps its current value, and a list that is given replaces the
  whole list.
- **Reject what can't be applied.** An unknown or misspelled key at any level,
  a value of the wrong type, an invalid regex, or an unreadable schema file
  makes the agent refuse the configuration (the proxy then does not use that
  connection), and the agent keeps running with what it had. A file with such
  a key fails at startup.
- **Authentication fails closed.** Leaving `auth` out never turns
  authentication off, and an `auth` section that lists `providers` without
  saying `enabled` turns it on. Only an explicit `enabled false` turns it off,
  and the agent logs a warning when that happens.
- **No secrets in logs.** The agent logs the block's hash and the names of
  the settings that changed, never the block itself.

```kdl
agent "mqtt-gateway" type="custom" {
    unix-socket "/var/run/zentinel/mqtt-gateway.sock"
    events "websocket_frame"
    config {
        rate-limit {
            enabled #true
            per-client messages-per-second=100 burst=50
        }
        retained enabled=#true allow-retained=#false allowed-topics="config/#"
    }
}
```

```json
{
  "auth": {
    "enabled": true,
    "allow-anonymous": false,
    "providers": [
      { "type": "file", "path": "/etc/zentinel/mqtt-users.json" }
    ]
  },
  "acl": {
    "enabled": true,
    "default-action": "deny",
    "rules": [
      {
        "name": "block-internal",
        "topics": ["$SYS/#", "internal/#"],
        "decision": "deny",
        "priority": 100
      },
      {
        "name": "sensors-publish",
        "match": { "username-regex": "^sensor-" },
        "topics": ["sensors/+/data"],
        "actions": ["publish"],
        "decision": "allow",
        "priority": 10
      },
      {
        "name": "operators-subscribe",
        "match": { "groups": ["operators"] },
        "topics": ["sensors/#"],
        "actions": ["subscribe"],
        "decision": "allow",
        "priority": 10
      }
    ]
  },
  "inspection": {
    "enabled": true,
    "max-payload-size": 262144,
    "patterns": { "sqli": true, "command-injection": true }
  },
  "rate-limit": {
    "enabled": true,
    "per-client": { "messages-per-second": 100, "bytes-per-second": 1048576, "burst": 50 }
  },
  "qos": { "enabled": true, "max-qos": 1, "downgrade": false },
  "retained": { "enabled": true, "allow-retained": false, "allowed-topics": ["config/#"] }
}
```

The user file for the `file` provider is JSON (other extensions fail to load):

```json
{
  "users": {
    "sensor-01": { "password_hash": "$2b$12$...", "groups": ["sensors"] }
  }
}
```

| Option | Default | Meaning |
|---|---|---|
| `auth.enabled` | `false`, or `true` when `auth.providers` is set | Authenticate `CONNECT`; when off every client is accepted |
| `auth.allow-anonymous` | `false` | Accept `CONNECT` without username and password |
| `auth.providers` | `[]` | Tried in order. `file` (`path`, `hot_reload`): bcrypt users with groups. `jwt` (`secret`, `issuer`, `audience`, `username_claim` = `sub`): HS256 token in the password field. `http` and `certificate` are accepted but not implemented, and `jwks_url` is not read |
| `auth.client-id-pattern` | none | Regex the client ID must match |
| `auth.min-client-id-length` / `max-client-id-length` | `1` / `128` | Client ID length bounds |
| `acl.enabled` | `true` | Evaluate ACL rules |
| `acl.default-action` | `deny` | Decision when no rule matches |
| `acl.rules[]` | `[]` | `name`, `topics`, `decision` (`allow`/`deny`), `priority` (higher first, first match wins), `actions` (empty means all), `match` (`username`, `username-regex`, `client-id`, `client-id-regex`, `client-ip`, `groups`, `protocol-version`) |
| `inspection.enabled` | `false` | Inspect `PUBLISH` payloads |
| `inspection.max-payload-size` | `262144` | Larger payloads are dropped |
| `inspection.patterns` | all off | `sqli`, `command-injection`, `script-injection`, `path-traversal`, plus `custom-patterns` (`name`, `pattern`, `severity`) |
| `inspection.json-schema` | none | `schema-file` and `topics` to validate JSON payloads against |
| `inspection.block-binary` | `false` | Drop payloads that are not UTF-8 |
| `inspection.exclude-topics` | `[]` | Topics not inspected |
| `rate-limit.enabled` | `false` | Apply rate limits to `PUBLISH` |
| `rate-limit.global` / `per-client` | none | `messages-per-second`, `bytes-per-second` (0 = off), `burst` (default `10`) |
| `rate-limit.per-topic` | `[]` | `topic` plus `limit` |
| `rate-limit.key-by` | `client_id` | Per-client key: `client_id`, `username` or `client_ip` |
| `qos.enabled` | `false` | Enforce a maximum QoS on `PUBLISH` |
| `qos.max-qos` / `per-topic` | `2` / `[]` | Maximum QoS, globally or per topic |
| `qos.downgrade` | `true` | When `true`, a higher QoS is let through unchanged (the frame is not rewritten); set `false` to drop it |
| `retained.enabled` | `false` | Apply retained-message rules |
| `retained.allow-retained` | `true` | Allow the retain flag outside `allowed-topics` |
| `retained.allowed-topics` / `blocked-topics` / `max-size` | `[]` / `[]` / none | Per-topic retain rules and a size cap |
| `general.block-mode` | `true` | `false` logs policy violations and forwards the frame |
| `general.log-packets` | `false` | Log every inspected frame at debug level |

Parsed but not used today: an ACL rule's `max-qos`, `acl.rules-file`,
`acl.cache-decisions`, `inspection.json-schema.block-on-failure` (schema
failures always drop), and `general.fail-open`, `protocol-versions`,
`max-connections-per-ip`, `connect-timeout-secs`.

Proxy-side options (`events`, `timeout-ms`, `failure-mode`):
<https://docs.zentinelproxy.io/configuration/agents/>. Agent reference:
<https://registry.zentinelproxy.io/mqtt-gateway/>.

## How it works

Only binary, client-to-server frames are inspected, and each frame is parsed as
one MQTT packet with `mqttrs`, which handles MQTT 3.1 and 3.1.1. A frame that
does not parse is dropped, so MQTT 5.0 clients do not work through the agent.

| Packet | Checks |
|---|---|
| `CONNECT` | Authentication and client ID rules; on failure the connection is closed with code `5` (the MQTT "not authorized" reason code, not a WebSocket 1008) |
| `PUBLISH` | ACL, rate limit, QoS, retained, payload inspection, in that order |
| `SUBSCRIBE` | ACL for each topic filter |
| `UNSUBSCRIBE` | ACL |
| `PINGREQ`, `PINGRESP`, other packets | Allowed |
| `DISCONNECT` | Allowed; connection state is removed |

`PUBLISH` or `SUBSCRIBE` before a successful `CONNECT` on the same connection
closes it. The agent exports v2 metrics for requests, blocks, auth failures,
ACL denials, rate-limit hits and inspection blocks.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Minimum Rust: 1.94.1 (`rust-version` in `Cargo.toml`).

## Related

- [Registry page](https://registry.zentinelproxy.io/mqtt-gateway/)
- [Agents configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)
- [WebSocket inspector agent](https://github.com/zentinelproxy/zentinel-agent-websocket-inspector), for text and JSON WebSocket traffic

## License

Apache-2.0, as declared in `Cargo.toml`. The repository has no `LICENSE` file yet.

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
