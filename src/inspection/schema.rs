//! JSON schema validation

use anyhow::{Context, Result};
use jsonschema::JSONSchema;
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// JSON Schema validator
pub struct SchemaValidator {
    validator: Arc<JSONSchema>,
}

impl SchemaValidator {
    /// Create a validator from a schema file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read schema file: {}", path.display()))?;

        let schema: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| "Failed to parse schema as JSON")?;

        let validator = JSONSchema::compile(&schema)
            .map_err(|e| anyhow::anyhow!("Failed to compile JSON schema: {}", e))?;

        Ok(Self {
            validator: Arc::new(validator),
        })
    }

    /// Create a validator from a JSON value
    pub fn from_value(schema: &serde_json::Value) -> Result<Self> {
        let validator = JSONSchema::compile(schema)
            .map_err(|e| anyhow::anyhow!("Failed to compile JSON schema: {}", e))?;

        Ok(Self {
            validator: Arc::new(validator),
        })
    }

    /// Validate a JSON string against the schema
    pub fn validate(&self, json_str: &str) -> Result<(), Vec<String>> {
        // Parse JSON
        let value: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => return Err(vec![format!("Invalid JSON: {}", e)]),
        };

        // Validate against schema
        if self.validator.is_valid(&value) {
            debug!("JSON schema validation passed");
            Ok(())
        } else {
            // Collect errors
            let error_messages: Vec<String> = self.validator
                .validate(&value)
                .err()
                .map(|errors| errors.map(|e| format!("{} at {}", e, e.instance_path)).collect())
                .unwrap_or_default();
            Err(error_messages)
        }
    }

    /// Check if valid without collecting errors
    pub fn is_valid(&self, json_str: &str) -> bool {
        match serde_json::from_str::<serde_json::Value>(json_str) {
            Ok(value) => self.validator.is_valid(&value),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_validator() -> SchemaValidator {
        let schema = json!({
            "type": "object",
            "properties": {
                "temperature": {
                    "type": "number",
                    "minimum": -50,
                    "maximum": 100
                },
                "humidity": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time"
                }
            },
            "required": ["temperature"]
        });

        SchemaValidator::from_value(&schema).unwrap()
    }

    #[test]
    fn test_valid_json() {
        let validator = create_test_validator();

        let result = validator.validate(r#"{"temperature": 25.5, "humidity": 60}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_required_field() {
        let validator = create_test_validator();

        let result = validator.validate(r#"{"humidity": 60}"#);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("required")));
    }

    #[test]
    fn test_invalid_type() {
        let validator = create_test_validator();

        let result = validator.validate(r#"{"temperature": "hot"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_range() {
        let validator = create_test_validator();

        let result = validator.validate(r#"{"temperature": 150}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_json() {
        let validator = create_test_validator();

        let result = validator.validate("not json at all");
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors[0].contains("Invalid JSON"));
    }

    #[test]
    fn test_is_valid() {
        let validator = create_test_validator();

        assert!(validator.is_valid(r#"{"temperature": 25}"#));
        assert!(!validator.is_valid(r#"{"humidity": 60}"#));
        assert!(!validator.is_valid("invalid json"));
    }
}
