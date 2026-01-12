//! Payload inspection module
//!
//! Provides detection of malicious patterns in MQTT message payloads.

mod patterns;
mod schema;

pub use patterns::{Detection, PatternInspector};
pub use schema::SchemaValidator;

use crate::config::InspectionConfig;
use crate::mqtt::TopicMatcher;
use tracing::debug;

/// Inspection result
#[derive(Debug, Clone)]
pub struct InspectionResult {
    /// Whether inspection passed (no threats detected)
    pub passed: bool,
    /// List of detections
    pub detections: Vec<Detection>,
    /// Whether to block (vs. log only)
    pub should_block: bool,
}

impl InspectionResult {
    pub fn passed() -> Self {
        Self {
            passed: true,
            detections: Vec::new(),
            should_block: false,
        }
    }

    pub fn failed(detections: Vec<Detection>, should_block: bool) -> Self {
        Self {
            passed: false,
            detections,
            should_block,
        }
    }
}

/// Payload inspector
pub struct PayloadInspector {
    pattern_inspector: PatternInspector,
    schema_validator: Option<SchemaValidator>,
    config: InspectionConfig,
    topic_matcher: TopicMatcher,
}

impl PayloadInspector {
    /// Create a new payload inspector from configuration
    pub fn new(config: &InspectionConfig) -> anyhow::Result<Self> {
        let pattern_inspector = PatternInspector::new(&config.patterns)?;

        let schema_validator = if let Some(ref schema_config) = config.json_schema {
            Some(SchemaValidator::from_file(&schema_config.schema_file)?)
        } else {
            None
        };

        Ok(Self {
            pattern_inspector,
            schema_validator,
            config: config.clone(),
            topic_matcher: TopicMatcher::new(),
        })
    }

    /// Inspect a message payload
    pub fn inspect(&self, topic: &str, payload: &[u8]) -> InspectionResult {
        if !self.config.enabled {
            return InspectionResult::passed();
        }

        // Check if topic is excluded
        for pattern in &self.config.exclude_topics {
            if self.topic_matcher.matches(topic, pattern) {
                debug!(topic = %topic, pattern = %pattern, "Topic excluded from inspection");
                return InspectionResult::passed();
            }
        }

        // Check payload size
        if self.config.max_payload_size > 0 && payload.len() > self.config.max_payload_size {
            return InspectionResult::failed(
                vec![Detection::new(
                    "size-limit",
                    format!("Payload size {} exceeds limit {}", payload.len(), self.config.max_payload_size),
                    crate::config::Severity::Medium,
                )],
                true,
            );
        }

        let mut all_detections = Vec::new();

        // Try to convert to string for text-based inspection
        match std::str::from_utf8(payload) {
            Ok(text) => {
                // Pattern-based inspection
                let detections = self.pattern_inspector.inspect(text);
                all_detections.extend(detections);

                // JSON schema validation (if configured for this topic)
                if let Some(ref validator) = self.schema_validator {
                    if let Some(ref schema_config) = self.config.json_schema {
                        let should_validate = schema_config.topics.iter()
                            .any(|p| self.topic_matcher.matches(topic, p));

                        if should_validate {
                            if let Err(errors) = validator.validate(text) {
                                for error in errors {
                                    all_detections.push(Detection::new(
                                        "schema-validation",
                                        error,
                                        crate::config::Severity::Medium,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Binary payload
                if self.config.block_binary {
                    return InspectionResult::failed(
                        vec![Detection::new(
                            "binary-payload",
                            "Binary payloads are not allowed".to_string(),
                            crate::config::Severity::Medium,
                        )],
                        true,
                    );
                }
            }
        }

        if all_detections.is_empty() {
            InspectionResult::passed()
        } else {
            InspectionResult::failed(all_detections, true)
        }
    }

    /// Reconfigure inspector
    pub fn reconfigure(&mut self, config: &InspectionConfig) -> anyhow::Result<()> {
        self.pattern_inspector = PatternInspector::new(&config.patterns)?;
        self.schema_validator = if let Some(ref schema_config) = config.json_schema {
            Some(SchemaValidator::from_file(&schema_config.schema_file)?)
        } else {
            None
        };
        self.config = config.clone();
        Ok(())
    }
}

impl Default for PayloadInspector {
    fn default() -> Self {
        Self {
            pattern_inspector: PatternInspector::default(),
            schema_validator: None,
            config: InspectionConfig::default(),
            topic_matcher: TopicMatcher::new(),
        }
    }
}
