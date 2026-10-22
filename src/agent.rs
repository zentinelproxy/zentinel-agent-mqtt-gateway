//! MQTT Gateway Agent implementation
//!
//! Implements the AgentHandlerV2 trait to process MQTT packets from WebSocket frames.

use crate::acl::{AclEvaluator, AclRequest};
use crate::auth::Authenticator;
use crate::config::{ConnectionContext, MqttAction, MqttGatewayConfig};
use crate::inspection::PayloadInspector;
use crate::mqtt::{parse_packet, MqttPacket, ParsedConnect, ParsedPublish, ParsedSubscribe};
use crate::qos::QosEnforcer;
use crate::ratelimit::RateLimiter;
use crate::retained::RetainedController;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::fingerprint::config_fingerprint;
use tracing::{debug, info, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthConfig,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, RequestHeadersEvent, WebSocketFrameEvent,
};

/// MQTT Gateway Agent
pub struct MqttGatewayAgent {
    /// Configuration
    config: Arc<RwLock<MqttGatewayConfig>>,
    /// Authenticator
    authenticator: Arc<RwLock<Authenticator>>,
    /// ACL evaluator
    acl: Arc<AclEvaluator>,
    /// Rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// Payload inspector
    inspector: Arc<RwLock<PayloadInspector>>,
    /// QoS enforcer
    qos_enforcer: Arc<QosEnforcer>,
    /// Retained message controller
    retained_controller: Arc<RetainedController>,
    /// Connection contexts (keyed by correlation_id)
    connections: DashMap<String, ConnectionContext>,
    /// Metrics: total requests processed
    requests_total: AtomicU64,
    /// Metrics: total requests blocked
    requests_blocked: AtomicU64,
    /// Metrics: total authentication failures
    auth_failures: AtomicU64,
    /// Metrics: total ACL denials
    acl_denials: AtomicU64,
    /// Metrics: total rate limit hits
    rate_limit_hits: AtomicU64,
    /// Metrics: total inspection blocks
    inspection_blocks: AtomicU64,
    /// Configuration version
    config_version: Arc<RwLock<Option<String>>>,
    /// Canonical hash of the last configuration accepted from the proxy.
    /// The mutex also serialises configures arriving on several connections.
    config_hash: Mutex<Option<u64>>,
}

impl MqttGatewayAgent {
    /// Create a new MQTT Gateway agent with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(MqttGatewayConfig::default())
    }

    /// Create a new MQTT Gateway agent with the given configuration
    pub fn with_config(config: MqttGatewayConfig) -> Result<Self> {
        let authenticator = Authenticator::new(&config.auth)?;
        let acl = AclEvaluator::new(&config.acl).map_err(|e| anyhow::anyhow!("{}", e))?;
        let rate_limiter = RateLimiter::new(&config.rate_limit);
        let inspector = PayloadInspector::new(&config.inspection)?;
        let qos_enforcer = QosEnforcer::new(&config.qos);
        let retained_controller = RetainedController::new(&config.retained);

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            authenticator: Arc::new(RwLock::new(authenticator)),
            acl: Arc::new(acl),
            rate_limiter: Arc::new(rate_limiter),
            inspector: Arc::new(RwLock::new(inspector)),
            qos_enforcer: Arc::new(qos_enforcer),
            retained_controller: Arc::new(retained_controller),
            connections: DashMap::new(),
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            acl_denials: AtomicU64::new(0),
            rate_limit_hits: AtomicU64::new(0),
            inspection_blocks: AtomicU64::new(0),
            config_version: Arc::new(RwLock::new(None)),
            config_hash: Mutex::new(None),
        })
    }

    /// Reconfigure the agent with a complete configuration.
    ///
    /// Only the components whose section changed are rebuilt, so runtime
    /// state (rate-limit buckets, authenticated connections, compiled
    /// patterns) survives a reconfigure that leaves its settings alone.
    /// Everything that can fail is built before anything is replaced, so an
    /// error leaves the agent exactly as it was.
    pub fn reconfigure(&self, config: MqttGatewayConfig) -> Result<()> {
        let current = serde_json::to_value(&*self.config.read())?;
        let next = serde_json::to_value(&config)?;
        let changed: Vec<&str> = ["auth", "acl", "inspection", "rate-limit", "qos", "retained"]
            .into_iter()
            .filter(|section| current.get(*section) != next.get(*section))
            .collect();
        let has = |section: &str| changed.contains(&section);

        let authenticator = if has("auth") {
            Some(Authenticator::new(&config.auth)?)
        } else {
            None
        };
        if has("acl") {
            // Compile the rules once to validate them before swapping.
            AclEvaluator::new(&config.acl).map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        let inspector = if has("inspection") {
            Some(PayloadInspector::new(&config.inspection)?)
        } else {
            None
        };

        if let Some(authenticator) = authenticator {
            *self.authenticator.write() = authenticator;
        }
        if has("acl") {
            self.acl
                .reconfigure(&config.acl)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        if has("rate-limit") {
            self.rate_limiter.reconfigure(&config.rate_limit);
        }
        if let Some(inspector) = inspector {
            *self.inspector.write() = inspector;
        }
        if has("qos") {
            self.qos_enforcer.reconfigure(&config.qos);
        }
        if has("retained") {
            self.retained_controller.reconfigure(&config.retained);
        }

        *self.config.write() = config;
        Ok(())
    }

    /// Apply a configuration received from the proxy. See
    /// [`AgentHandlerV2::on_configure`] for the rules.
    ///
    /// Returns the names of the settings that changed.
    pub fn apply_proxy_config(&self, raw: &serde_json::Value) -> Result<Vec<String>> {
        let hash = config_fingerprint(raw);
        let mut last = self.config_hash.lock();
        if *last == Some(hash) {
            return Ok(Vec::new());
        }
        let (next, changed) = self
            .config
            .read()
            .merged(raw)
            .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
        if !changed.is_empty() {
            let auth_was_on = self.config.read().auth.enabled;
            if auth_was_on && !next.auth.enabled {
                warn!("Configuration turns MQTT authentication off (auth.enabled false)");
            }
            self.reconfigure(next)?;
        }
        *last = Some(hash);
        Ok(changed)
    }

    /// Process an MQTT packet from a WebSocket frame
    fn process_mqtt_packet(
        &self,
        correlation_id: &str,
        client_ip: &str,
        data: &[u8],
    ) -> AgentResponse {
        // Parse MQTT packet
        let packet = match parse_packet(data) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to parse MQTT packet");
                return self.block_response("mqtt-parse-error", "Invalid MQTT packet");
            }
        };

        match packet {
            MqttPacket::Connect(connect) => {
                self.handle_connect(correlation_id, client_ip, &connect)
            }
            MqttPacket::Publish(publish) => self.handle_publish(correlation_id, &publish),
            MqttPacket::Subscribe(subscribe) => self.handle_subscribe(correlation_id, &subscribe),
            MqttPacket::Unsubscribe(unsubscribe) => {
                self.handle_unsubscribe(correlation_id, &unsubscribe.topics)
            }
            MqttPacket::Disconnect => self.handle_disconnect(correlation_id),
            MqttPacket::PingReq | MqttPacket::PingResp => {
                // Allow ping/pong
                AgentResponse::websocket_allow()
            }
            MqttPacket::Other(_) => {
                // Allow other packets (CONNACK, PUBACK, etc.) - these are from broker
                AgentResponse::websocket_allow()
            }
        }
    }

    /// Handle CONNECT packet
    fn handle_connect(
        &self,
        correlation_id: &str,
        client_ip: &str,
        connect: &ParsedConnect,
    ) -> AgentResponse {
        info!(
            client_id = %connect.client_id,
            client_ip = %client_ip,
            protocol_version = connect.protocol_version,
            "MQTT CONNECT"
        );

        // Authenticate
        let auth_result = self.authenticator.read().authenticate(connect, client_ip);

        if !auth_result.authenticated {
            warn!(
                client_id = %connect.client_id,
                reason = ?auth_result.reason,
                "Authentication failed"
            );
            self.auth_failures.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.close_connection(
                "auth-failed",
                auth_result
                    .reason
                    .as_deref()
                    .unwrap_or("Authentication failed"),
                0x05, // Not authorized
            );
        }

        // Create connection context
        let mut context = ConnectionContext {
            client_id: connect.client_id.clone(),
            username: connect.username.clone(),
            client_ip: client_ip.to_string(),
            protocol_version: connect.protocol_version,
            groups: Vec::new(),
            attributes: Default::default(),
        };

        // Apply auth result to context
        self.authenticator
            .read()
            .apply_to_context(&mut context, &auth_result);

        // Store context
        self.connections.insert(correlation_id.to_string(), context);

        debug!(client_id = %connect.client_id, "CONNECT allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec![
                "mqtt".to_string(),
                "connect".to_string(),
                "success".to_string(),
            ],
            ..Default::default()
        })
    }

    /// Handle PUBLISH packet
    fn handle_publish(&self, correlation_id: &str, publish: &ParsedPublish) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                warn!("PUBLISH without CONNECT context");
                return self.close_connection("no-context", "No connection context", 0x01);
            }
        };

        debug!(
            client_id = %context.client_id,
            topic = %publish.topic,
            qos = publish.qos,
            retain = publish.retain,
            size = publish.payload.len(),
            "MQTT PUBLISH"
        );

        // ACL check
        let acl_result = self.acl.evaluate(&AclRequest {
            context: &context,
            topic: &publish.topic,
            action: MqttAction::Publish,
            qos: Some(publish.qos),
        });

        if !acl_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                rule = ?acl_result.rule_name,
                "PUBLISH denied by ACL"
            );
            self.acl_denials.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response("acl-denied", &acl_result.reason);
        }

        // Rate limit check
        let rate_result =
            self.rate_limiter
                .check_message(&context, &publish.topic, publish.payload.len());

        if !rate_result.allowed {
            info!(
                client_id = %context.client_id,
                limit = ?rate_result.exceeded_limit,
                "PUBLISH rate limited"
            );
            self.rate_limit_hits.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response(
                "rate-limited",
                &format!("Rate limit exceeded: {:?}", rate_result.exceeded_limit),
            );
        }

        // QoS check
        let qos_result = self.qos_enforcer.check(&publish.topic, publish.qos);
        if !qos_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                qos = publish.qos,
                "PUBLISH QoS denied"
            );
            return self.drop_response(
                "qos-denied",
                qos_result.reason.as_deref().unwrap_or("QoS not allowed"),
            );
        }

        // Retained message check
        let retained_result =
            self.retained_controller
                .check(&publish.topic, publish.payload.len(), publish.retain);

        if !retained_result.allowed {
            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                "Retained message denied"
            );
            return self.drop_response(
                "retained-denied",
                retained_result
                    .reason
                    .as_deref()
                    .unwrap_or("Retained not allowed"),
            );
        }

        // Payload inspection
        let inspection_result = self
            .inspector
            .read()
            .inspect(&publish.topic, &publish.payload);

        if !inspection_result.passed && inspection_result.should_block {
            let patterns: Vec<_> = inspection_result
                .detections
                .iter()
                .map(|d| d.pattern_id.clone())
                .collect();

            info!(
                client_id = %context.client_id,
                topic = %publish.topic,
                patterns = ?patterns,
                "PUBLISH blocked by inspection"
            );
            self.inspection_blocks.fetch_add(1, Ordering::Relaxed);
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
            return self.drop_response(
                "inspection-blocked",
                &format!("Malicious pattern detected: {:?}", patterns),
            );
        }

        // All checks passed
        debug!(client_id = %context.client_id, topic = %publish.topic, "PUBLISH allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "publish".to_string()],
            ..Default::default()
        })
    }

    /// Handle SUBSCRIBE packet
    fn handle_subscribe(&self, correlation_id: &str, subscribe: &ParsedSubscribe) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                warn!("SUBSCRIBE without CONNECT context");
                return self.close_connection("no-context", "No connection context", 0x01);
            }
        };

        debug!(
            client_id = %context.client_id,
            topics = ?subscribe.subscriptions.iter().map(|s| &s.topic_filter).collect::<Vec<_>>(),
            "MQTT SUBSCRIBE"
        );

        // Check ACL for each topic filter
        for sub in &subscribe.subscriptions {
            let acl_result = self.acl.evaluate(&AclRequest {
                context: &context,
                topic: &sub.topic_filter,
                action: MqttAction::Subscribe,
                qos: Some(sub.qos),
            });

            if !acl_result.allowed {
                info!(
                    client_id = %context.client_id,
                    topic = %sub.topic_filter,
                    rule = ?acl_result.rule_name,
                    "SUBSCRIBE denied by ACL"
                );
                self.acl_denials.fetch_add(1, Ordering::Relaxed);
                self.requests_blocked.fetch_add(1, Ordering::Relaxed);
                return self.drop_response("acl-denied", &acl_result.reason);
            }
        }

        debug!(client_id = %context.client_id, "SUBSCRIBE allowed");
        AgentResponse::websocket_allow().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "subscribe".to_string()],
            ..Default::default()
        })
    }

    /// Handle UNSUBSCRIBE packet
    fn handle_unsubscribe(&self, correlation_id: &str, topics: &[String]) -> AgentResponse {
        let context = match self.connections.get(correlation_id) {
            Some(ctx) => ctx.clone(),
            None => {
                return AgentResponse::websocket_allow();
            }
        };

        debug!(
            client_id = %context.client_id,
            topics = ?topics,
            "MQTT UNSUBSCRIBE"
        );

        // Check ACL for unsubscribe (if you want to control this)
        for topic in topics {
            let acl_result = self.acl.evaluate(&AclRequest {
                context: &context,
                topic,
                action: MqttAction::Unsubscribe,
                qos: None,
            });

            if !acl_result.allowed {
                return self.drop_response("acl-denied", &acl_result.reason);
            }
        }

        AgentResponse::websocket_allow()
    }

    /// Handle DISCONNECT packet
    fn handle_disconnect(&self, correlation_id: &str) -> AgentResponse {
        if let Some((_, context)) = self.connections.remove(correlation_id) {
            debug!(client_id = %context.client_id, "MQTT DISCONNECT");
        }
        AgentResponse::websocket_allow()
    }

    /// Create a drop response (drop the frame)
    fn drop_response(&self, rule: &str, reason: &str) -> AgentResponse {
        let config = self.config.read();

        if config.general.block_mode {
            AgentResponse::websocket_drop().with_audit(AuditMetadata {
                tags: vec!["mqtt".to_string(), "blocked".to_string()],
                rule_ids: vec![rule.to_string()],
                reason_codes: vec![reason.to_string()],
                ..Default::default()
            })
        } else {
            // Detect-only mode: allow but log
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["mqtt".to_string(), "detect-only".to_string()],
                rule_ids: vec![rule.to_string()],
                reason_codes: vec![reason.to_string()],
                ..Default::default()
            })
        }
    }

    /// Create a block response (for non-WebSocket errors)
    fn block_response(&self, rule: &str, reason: &str) -> AgentResponse {
        AgentResponse::websocket_drop().with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "error".to_string()],
            rule_ids: vec![rule.to_string()],
            reason_codes: vec![reason.to_string()],
            ..Default::default()
        })
    }

    /// Create a close connection response
    fn close_connection(&self, rule: &str, reason: &str, code: u16) -> AgentResponse {
        AgentResponse::websocket_close(code, reason.to_string()).with_audit(AuditMetadata {
            tags: vec!["mqtt".to_string(), "connection-closed".to_string()],
            rule_ids: vec![rule.to_string()],
            reason_codes: vec![reason.to_string()],
            ..Default::default()
        })
    }
}

impl Default for MqttGatewayAgent {
    fn default() -> Self {
        Self::new().expect("Failed to create default MqttGatewayAgent")
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for MqttGatewayAgent {
    /// Return agent capabilities for v2 protocol negotiation
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "mqtt-gateway".to_string(),
            name: "MQTT Gateway Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![
                EventType::Configure,
                EventType::RequestHeaders,
                EventType::WebSocketFrame,
            ],
            features: AgentFeatures {
                streaming_body: false,
                websocket: true,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: 10 * 1024 * 1024, // 10MB
                max_concurrency: 100,
                preferred_chunk_size: 64 * 1024, // 64KB
                max_memory: None,
                max_processing_time_ms: Some(5000),
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle configuration updates from the proxy
    /// The proxy sends the agent's `config { }` block on every connection
    /// (each pooled connection, and every reconnect), so this is idempotent:
    /// a block identical to the last one accepted, or one that changes no
    /// setting, leaves all state alone. The block overlays the running
    /// configuration (absent keys keep their value); unknown keys are
    /// rejected. The configuration itself is never logged, since it may hold
    /// secrets (JWT secrets, provider headers); its hash and the changed
    /// setting names are.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        let hash = format!("{:016x}", config_fingerprint(&config));
        match self.apply_proxy_config(&config) {
            Ok(changed) => {
                if changed.is_empty() {
                    debug!(version = ?version, config_hash = %hash, "Configuration unchanged");
                } else {
                    info!(
                        version = ?version,
                        config_hash = %hash,
                        changed = ?changed,
                        "Configuration applied"
                    );
                }
                if let Some(v) = version {
                    *self.config_version.write() = Some(v);
                }
                true
            }
            Err(e) => {
                warn!(version = ?version, config_hash = %hash, error = %e, "Configuration rejected");
                false
            }
        }
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        // We only handle WebSocket frames
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.requests_total.fetch_add(1, Ordering::Relaxed);

        // Only inspect binary frames (MQTT over WebSocket)
        if event.opcode != "binary" {
            return AgentResponse::websocket_allow();
        }

        // Only inspect client-to-server frames
        if !event.client_to_server {
            return AgentResponse::websocket_allow();
        }

        // Decode base64 payload
        let data = match BASE64.decode(&event.data) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to decode WebSocket frame data");
                return AgentResponse::websocket_allow();
            }
        };

        // Log if configured
        if self.config.read().general.log_packets {
            debug!(
                correlation_id = %event.correlation_id,
                frame_index = event.frame_index,
                size = data.len(),
                "Processing MQTT frame"
            );
        }

        // Process the MQTT packet
        self.process_mqtt_packet(&event.correlation_id, &event.client_ip, &data)
    }

    /// Return current health status
    fn health_status(&self) -> HealthStatus {
        let connections = self.connections.len() as u32;
        let requests = self.requests_total.load(Ordering::Relaxed);
        let blocked = self.requests_blocked.load(Ordering::Relaxed);

        let mut status = HealthStatus::healthy("mqtt-gateway");
        status.load = Some(zentinel_agent_protocol::v2::LoadMetrics {
            in_flight: connections,
            queue_depth: 0,
            avg_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            requests_processed: requests,
            requests_rejected: blocked,
            requests_timed_out: 0,
        });
        status
    }

    /// Return metrics report for export
    fn metrics_report(&self) -> Option<MetricsReport> {
        use zentinel_agent_protocol::v2::{CounterMetric, GaugeMetric};

        let mut report = MetricsReport::new("mqtt-gateway", 10_000);

        report.counters.push(CounterMetric::new(
            "mqtt_gateway_requests_total",
            self.requests_total.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_auth_failures_total",
            self.auth_failures.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_acl_denials_total",
            self.acl_denials.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_rate_limit_hits_total",
            self.rate_limit_hits.load(Ordering::Relaxed),
        ));
        report.counters.push(CounterMetric::new(
            "mqtt_gateway_inspection_blocks_total",
            self.inspection_blocks.load(Ordering::Relaxed),
        ));
        report.gauges.push(GaugeMetric::new(
            "mqtt_gateway_active_connections",
            self.connections.len() as f64,
        ));

        Some(report)
    }

    /// Handle shutdown request from proxy
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Clear connection contexts on shutdown
        self.connections.clear();
    }

    /// Handle drain request from proxy
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );
        // In drain mode, we continue processing existing connections
        // but the proxy will stop sending new ones
    }
}

#[cfg(test)]
mod configure_tests {
    use super::*;
    use crate::config::{RateLimit, RateLimitConfig};
    use serde_json::json;

    fn client() -> ConnectionContext {
        ConnectionContext {
            client_id: "sensor-1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            protocol_version: 4,
            ..Default::default()
        }
    }

    fn limited_agent() -> MqttGatewayAgent {
        let config = MqttGatewayConfig {
            rate_limit: RateLimitConfig {
                enabled: true,
                per_client: Some(RateLimit {
                    messages_per_second: 1,
                    bytes_per_second: 0,
                    burst: 3,
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        MqttGatewayAgent::with_config(config).unwrap()
    }

    fn allowed(agent: &MqttGatewayAgent) -> bool {
        agent
            .rate_limiter
            .check_message(&client(), "sensors/1/data", 10)
            .allowed
    }

    #[tokio::test]
    async fn identical_configure_keeps_rate_limit_buckets() {
        let agent = limited_agent();
        let block = json!({
            "rate-limit": {
                "enabled": true,
                "per-client": {"messages-per-second": 1, "burst": 3}
            }
        });
        assert!(agent.on_configure(block.clone(), None).await);
        for _ in 0..3 {
            assert!(allowed(&agent));
        }
        // Another pooled connection, or a reconnect, sends the same block.
        assert!(agent.on_configure(block.clone(), None).await);
        assert!(
            !allowed(&agent),
            "a repeated configure must not refill the bucket"
        );
    }

    #[tokio::test]
    async fn unrelated_change_keeps_rate_limit_buckets() {
        let agent = limited_agent();
        for _ in 0..3 {
            assert!(allowed(&agent));
        }
        assert!(
            agent
                .on_configure(json!({"qos": {"max-qos": 1}}), None)
                .await
        );
        assert!(!allowed(&agent));
        // Changing the limit itself does rebuild the per-client buckets.
        let raised = json!({"rate-limit": {"per-client": {"messages-per-second": 1, "burst": 5}}});
        assert!(agent.on_configure(raised, None).await);
        assert!(allowed(&agent));
    }

    fn file_config() -> MqttGatewayConfig {
        MqttGatewayConfig::from_json(&json!({
            "auth": {
                "enabled": true,
                "providers": [{"type": "jwt", "secret": "file-secret"}]
            },
            "acl": {
                "default-action": "allow",
                "rules": [{"name": "deny-sys", "topics": ["$SYS/#"], "decision": "deny"}]
            },
            "inspection": {"enabled": true, "patterns": {"sqli": true}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn partial_configure_keeps_file_values() {
        let agent = MqttGatewayAgent::with_config(file_config()).unwrap();
        // A block that does not mention auth, acl or inspection.
        assert!(
            agent
                .on_configure(json!({"qos": {"enabled": true, "max-qos": 1}}), None)
                .await
        );
        {
            let config = agent.config.read();
            assert!(config.auth.enabled, "omitting auth must not turn it off");
            assert_eq!(config.auth.providers.len(), 1);
            assert_eq!(config.acl.rules.len(), 1);
            assert!(config.inspection.enabled);
            assert!(config.inspection.patterns.sqli);
            assert!(config.qos.enabled);
            assert_eq!(config.qos.max_qos, 1);
        }
        // Nested merge: one field of a section leaves its siblings alone.
        assert!(
            agent
                .on_configure(json!({"auth": {"allow-anonymous": true}}), None)
                .await
        );
        let config = agent.config.read();
        assert!(config.auth.enabled);
        assert!(config.auth.allow_anonymous);
        assert_eq!(config.auth.providers.len(), 1);
    }

    #[tokio::test]
    async fn providers_without_enabled_turn_auth_on() {
        let agent = MqttGatewayAgent::new().unwrap();
        assert!(!agent.config.read().auth.enabled);
        // What a KDL `auth { providers { type "jwt"; secret "s" } }` sends.
        let block = json!({"auth": {"providers": {"type": "jwt", "secret": "s"}}});
        assert!(agent.on_configure(block, None).await);
        assert!(agent.config.read().auth.enabled);
        assert_eq!(agent.config.read().auth.providers.len(), 1);
        // Only an explicit false turns it off.
        assert!(
            agent
                .on_configure(json!({"auth": {"enabled": false}}), None)
                .await
        );
        assert!(!agent.config.read().auth.enabled);
    }

    #[tokio::test]
    async fn unknown_keys_are_rejected_and_nothing_changes() {
        let agent = MqttGatewayAgent::with_config(file_config()).unwrap();
        for bad in [
            json!({"auht": {"enabled": false}}),
            json!({"auth": {"enable": false}}),
            json!({"rate-limit": {"per-clinet": {"messages-per-second": 1}}}),
            json!({"auth": {"providers": [{"type": "jwt", "secrte": "x"}]}}),
            json!({"acl": {"rules": [{"name": "r", "topics": "a/#", "decision": "allow", "prio": 1}]}}),
            json!([1, 2]),
        ] {
            assert!(
                !agent.on_configure(bad.clone(), None).await,
                "{bad} accepted"
            );
        }
        let config = agent.config.read();
        assert!(config.auth.enabled);
        assert_eq!(config.acl.rules.len(), 1);
        assert_eq!(config.acl.rules[0].name, "deny-sys");
    }

    #[tokio::test]
    async fn single_value_lists_from_kdl() {
        let agent = MqttGatewayAgent::new().unwrap();
        let block = json!({"retained": {"enabled": true, "allowed-topics": "config/#"}});
        assert!(agent.on_configure(block, None).await);
        assert_eq!(
            agent.config.read().retained.allowed_topics,
            vec!["config/#".to_string()]
        );
    }
}
