//! Configuration types for the MQTT Gateway agent
//!
//! Provides JSON-serializable configuration for authentication, ACLs,
//! payload inspection, rate limiting, QoS enforcement, and retained message control.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// MQTT Gateway Agent Configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct MqttGatewayConfig {
    /// Authentication configuration
    pub auth: AuthConfig,

    /// Access Control Lists
    pub acl: AclConfig,

    /// Payload inspection settings
    pub inspection: InspectionConfig,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// QoS enforcement settings
    pub qos: QosConfig,

    /// Retained message control
    pub retained: RetainedConfig,

    /// General settings
    pub general: GeneralConfig,
}

// ============================================================================
// Authentication Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Enable authentication
    pub enabled: bool,

    /// Allow anonymous connections (no username/password)
    pub allow_anonymous: bool,

    /// Authentication providers (evaluated in order)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub providers: Vec<AuthProvider>,

    /// Client ID validation regex pattern
    pub client_id_pattern: Option<String>,

    /// Minimum client ID length
    #[serde(default = "default_min_client_id_len")]
    pub min_client_id_length: usize,

    /// Maximum client ID length
    #[serde(default = "default_max_client_id_len")]
    pub max_client_id_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", deny_unknown_fields)]
pub enum AuthProvider {
    /// Static username/password file (YAML or JSON)
    File {
        path: PathBuf,
        /// Reload file on every auth check (for development)
        #[serde(default)]
        hot_reload: bool,
    },

    /// HTTP-based authentication
    Http {
        url: String,
        #[serde(default = "default_http_timeout")]
        timeout_ms: u64,
        /// Headers to include in auth request
        #[serde(default)]
        headers: HashMap<String, String>,
    },

    /// JWT validation
    Jwt {
        /// Expected issuer claim
        issuer: Option<String>,
        /// Expected audience claim
        audience: Option<String>,
        /// JWKS URL for key retrieval
        jwks_url: Option<String>,
        /// Static secret for HMAC algorithms
        secret: Option<String>,
        /// Claim to extract as username
        #[serde(default = "default_username_claim")]
        username_claim: String,
    },

    /// Extract identity from TLS client certificate
    Certificate {
        /// Which certificate field to use as username
        #[serde(default)]
        extract_from: CertificateField,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CertificateField {
    #[default]
    CommonName,
    SubjectAlternativeName,
    SerialNumber,
}

// ============================================================================
// ACL Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct AclConfig {
    /// Enable ACL enforcement
    pub enabled: bool,

    /// Default action when no rule matches
    pub default_action: AclAction,

    /// ACL rules (evaluated in order, first match wins)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub rules: Vec<AclRule>,

    /// Load additional rules from file
    pub rules_file: Option<PathBuf>,

    /// Cache ACL decisions per connection
    #[serde(default = "default_true")]
    pub cache_decisions: bool,
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: AclAction::Deny,
            rules: Vec::new(),
            rules_file: None,
            cache_decisions: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AclRule {
    /// Rule name (for logging and debugging)
    pub name: String,

    /// Match conditions (all must match)
    #[serde(default, rename = "match")]
    pub match_conditions: AclMatch,

    /// Topic patterns this rule applies to
    #[serde(deserialize_with = "one_or_many")]
    pub topics: Vec<String>,

    /// Actions this rule applies to (empty = all actions)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub actions: Vec<MqttAction>,

    /// Decision: allow or deny
    pub decision: AclAction,

    /// Maximum QoS allowed (for publish/subscribe)
    pub max_qos: Option<u8>,

    /// Priority (higher = evaluated first, default = 0)
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct AclMatch {
    /// Match by exact username
    pub username: Option<String>,
    /// Match by username regex
    pub username_regex: Option<String>,
    /// Match by exact client ID
    pub client_id: Option<String>,
    /// Match by client ID regex
    pub client_id_regex: Option<String>,
    /// Match by client IP (CIDR notation supported)
    pub client_ip: Option<String>,
    /// Match if user belongs to any of these groups
    #[serde(default, deserialize_with = "opt_one_or_many")]
    pub groups: Option<Vec<String>>,
    /// Match by protocol version (3, 4, or 5)
    pub protocol_version: Option<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MqttAction {
    Connect,
    Publish,
    Subscribe,
    Unsubscribe,
}

// ============================================================================
// Payload Inspection Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct InspectionConfig {
    /// Enable payload inspection
    pub enabled: bool,

    /// Maximum payload size to inspect (bytes, 0 = unlimited)
    #[serde(default = "default_max_payload")]
    pub max_payload_size: usize,

    /// Malicious pattern detection
    pub patterns: PatternConfig,

    /// JSON schema validation
    pub json_schema: Option<JsonSchemaConfig>,

    /// Block binary payloads (non-UTF8)
    #[serde(default)]
    pub block_binary: bool,

    /// Topics to exclude from inspection (glob patterns)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_topics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct PatternConfig {
    /// Enable SQL injection detection
    pub sqli: bool,
    /// Enable command injection detection
    pub command_injection: bool,
    /// Enable script/XSS injection detection
    pub script_injection: bool,
    /// Enable path traversal detection
    pub path_traversal: bool,
    /// Custom regex patterns to block
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub custom_patterns: Vec<CustomPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CustomPattern {
    /// Pattern name for logging
    pub name: String,
    /// Regex pattern
    pub pattern: String,
    /// Severity level
    #[serde(default)]
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct JsonSchemaConfig {
    /// Path to JSON schema file
    pub schema_file: PathBuf,
    /// Topics to validate (glob patterns)
    #[serde(deserialize_with = "one_or_many")]
    pub topics: Vec<String>,
    /// Block on validation failure (vs. log only)
    #[serde(default = "default_true")]
    pub block_on_failure: bool,
}

// ============================================================================
// Rate Limiting Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Global rate limit (across all clients)
    pub global: Option<RateLimit>,

    /// Per-client rate limit
    pub per_client: Option<RateLimit>,

    /// Per-topic rate limits
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub per_topic: Vec<TopicRateLimit>,

    /// Rate limit key extraction (what identifies a client)
    #[serde(default)]
    pub key_by: RateLimitKey,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    #[default]
    ClientId,
    Username,
    ClientIp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RateLimit {
    /// Maximum messages per second
    pub messages_per_second: u32,
    /// Maximum bytes per second
    #[serde(default)]
    pub bytes_per_second: u64,
    /// Burst allowance (tokens)
    #[serde(default = "default_burst")]
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TopicRateLimit {
    /// Topic pattern (glob)
    pub topic: String,
    /// Rate limit for this topic
    pub limit: RateLimit,
}

// ============================================================================
// QoS Enforcement Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct QosConfig {
    /// Enable QoS enforcement
    pub enabled: bool,

    /// Maximum allowed QoS level (0, 1, or 2)
    pub max_qos: u8,

    /// Downgrade QoS to max instead of rejecting
    pub downgrade: bool,

    /// Per-topic QoS limits
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub per_topic: Vec<TopicQosLimit>,
}

impl Default for QosConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_qos: 2,
            downgrade: true,
            per_topic: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TopicQosLimit {
    /// Topic pattern
    pub topic: String,
    /// Maximum QoS for this topic
    pub max_qos: u8,
}

// ============================================================================
// Retained Message Control Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct RetainedConfig {
    /// Enable retained message control
    pub enabled: bool,

    /// Allow retained messages globally
    pub allow_retained: bool,

    /// Topics where retained messages are allowed (glob patterns)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub allowed_topics: Vec<String>,

    /// Topics where retained messages are blocked (glob patterns)
    #[serde(default)]
    #[serde(deserialize_with = "one_or_many")]
    pub blocked_topics: Vec<String>,

    /// Maximum retained message size (bytes)
    pub max_size: Option<usize>,
}

impl Default for RetainedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_retained: true,
            allowed_topics: Vec::new(),
            blocked_topics: Vec::new(),
            max_size: None,
        }
    }
}

// ============================================================================
// General Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct GeneralConfig {
    /// Block mode: block violations (true) or detect-only (false)
    pub block_mode: bool,

    /// Fail open on processing errors
    pub fail_open: bool,

    /// Log all MQTT packets (verbose)
    pub log_packets: bool,

    /// Supported MQTT protocol versions
    #[serde(default = "default_protocol_versions")]
    #[serde(deserialize_with = "one_or_many")]
    pub protocol_versions: Vec<MqttVersion>,

    /// Maximum connections per client IP
    pub max_connections_per_ip: Option<u32>,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            block_mode: true,
            fail_open: false,
            log_packets: false,
            protocol_versions: default_protocol_versions(),
            max_connections_per_ip: None,
            connect_timeout_secs: default_connect_timeout(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MqttVersion {
    #[serde(rename = "3.1")]
    V3_1,
    #[serde(rename = "3.1.1")]
    V3_1_1,
    #[serde(rename = "5.0")]
    V5_0,
}

// ============================================================================
// Connection Context (runtime state per connection)
// ============================================================================

/// Runtime context for an MQTT connection
#[derive(Debug, Clone, Default)]
pub struct ConnectionContext {
    /// Client ID from CONNECT
    pub client_id: String,
    /// Username from CONNECT (if provided)
    pub username: Option<String>,
    /// Client IP address
    pub client_ip: String,
    /// Protocol version
    pub protocol_version: u8,
    /// Authenticated user groups
    pub groups: Vec<String>,
    /// Custom attributes from auth provider
    pub attributes: HashMap<String, String>,
}

// ============================================================================
// Applying a configuration on top of the running one
// ============================================================================

/// Accept a list as an array or as a single value. A one-argument KDL node
/// (`topics "sensors/#"`) reaches the agent as a scalar, not an array.
fn one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match OneOrMany::<T>::deserialize(deserializer)? {
        OneOrMany::Many(v) => v,
        OneOrMany::One(v) => vec![v],
    })
}

fn opt_one_or_many<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    Ok(match Option::<OneOrMany<T>>::deserialize(deserializer)? {
        None => None,
        Some(OneOrMany::Many(v)) => Some(v),
        Some(OneOrMany::One(v)) => Some(vec![v]),
    })
}

/// Overlay `patch` onto `base`: objects merge key by key, anything else
/// (scalars, arrays, null) replaces the value at that key.
fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                match base.get_mut(key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        merge_json(existing, value)
                    }
                    _ => {
                        base.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (base, patch) => *base = patch.clone(),
    }
}

/// Dotted paths of every leaf that differs between `old` and `new`.
fn diff_paths(
    prefix: &str,
    old: &serde_json::Value,
    new: &serde_json::Value,
    out: &mut Vec<String>,
) {
    match (old, new) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => diff_paths(&path, x, y, out),
                    _ => out.push(path),
                }
            }
        }
        (a, b) if a != b => out.push(prefix.to_string()),
        _ => {}
    }
}

impl MqttGatewayConfig {
    /// The configuration that results from applying `patch` (a JSON
    /// document from the `--config` file or from the proxy's `config { }`
    /// block) on top of `self`, and the dotted names of the settings that
    /// changed.
    ///
    /// - Keys absent from `patch` keep their current value; objects merge,
    ///   other values (including lists) replace.
    /// - Unknown or misspelled keys are an error, never ignored.
    /// - Authentication fails closed: an `auth` object that lists providers
    ///   but does not say `enabled` turns authentication on. Only an explicit
    ///   `"enabled": false` turns it off.
    pub fn merged(&self, patch: &serde_json::Value) -> Result<(Self, Vec<String>), String> {
        if !patch.is_object() {
            return Err("configuration must be a JSON object".to_string());
        }
        let current = serde_json::to_value(self).map_err(|e| e.to_string())?;
        let mut next = current.clone();
        merge_json(&mut next, patch);

        if let Some(auth) = patch.get("auth").and_then(|a| a.as_object()) {
            let lists_providers = match auth.get("providers") {
                Some(serde_json::Value::Array(p)) => !p.is_empty(),
                Some(serde_json::Value::Object(_)) => true,
                _ => false,
            };
            if lists_providers && !auth.contains_key("enabled") {
                next["auth"]["enabled"] = serde_json::Value::Bool(true);
            }
        }

        let config: Self = serde_json::from_value(next).map_err(|e| e.to_string())?;
        // Diff the round-tripped value so defaults filled in by serde count.
        let new_value = serde_json::to_value(&config).map_err(|e| e.to_string())?;
        let mut changed = Vec::new();
        diff_paths("", &current, &new_value, &mut changed);
        Ok((config, changed))
    }

    /// Load a `--config` file's JSON on top of the built-in defaults, with
    /// the same rules as [`MqttGatewayConfig::merged`].
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        Self::default().merged(value).map(|(config, _)| config)
    }
}

// ============================================================================
// Default value functions
// ============================================================================

fn default_true() -> bool {
    true
}

fn default_min_client_id_len() -> usize {
    1
}

fn default_max_client_id_len() -> usize {
    128
}

fn default_http_timeout() -> u64 {
    5000
}

fn default_username_claim() -> String {
    "sub".to_string()
}

fn default_max_payload() -> usize {
    256 * 1024 // 256KB
}

fn default_burst() -> u32 {
    10
}

fn default_protocol_versions() -> Vec<MqttVersion> {
    vec![MqttVersion::V3_1_1, MqttVersion::V5_0]
}

fn default_connect_timeout() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MqttGatewayConfig::default();
        assert!(!config.auth.enabled);
        assert!(config.acl.enabled);
        assert_eq!(config.acl.default_action, AclAction::Deny);
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "auth": {
                "enabled": true,
                "allow-anonymous": false,
                "providers": [
                    {"type": "file", "path": "/etc/mqtt/users.yaml"}
                ]
            },
            "acl": {
                "enabled": true,
                "default-action": "deny",
                "rules": [
                    {
                        "name": "sensor-publish",
                        "match": {"username-regex": "^sensor-"},
                        "topics": ["sensors/+/data"],
                        "actions": ["publish"],
                        "decision": "allow"
                    }
                ]
            }
        }"#;

        let config: MqttGatewayConfig = serde_json::from_str(json).expect("Failed to parse");
        assert!(config.auth.enabled);
        assert!(!config.auth.allow_anonymous);
        assert_eq!(config.acl.rules.len(), 1);
        assert_eq!(config.acl.rules[0].name, "sensor-publish");
    }
}
