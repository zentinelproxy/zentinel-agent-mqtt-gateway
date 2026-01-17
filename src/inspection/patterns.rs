//! Malicious pattern detection

use crate::config::{PatternConfig, Severity};
use regex::Regex;
use tracing::warn;

/// A single detection
#[derive(Debug, Clone)]
pub struct Detection {
    /// Pattern ID that triggered
    pub pattern_id: String,
    /// Description of what was detected
    pub description: String,
    /// Severity level
    pub severity: Severity,
}

impl Detection {
    pub fn new(pattern_id: &str, description: String, severity: Severity) -> Self {
        Self {
            pattern_id: pattern_id.to_string(),
            description,
            severity,
        }
    }
}

/// Compiled pattern for matching
struct CompiledPattern {
    id: String,
    regex: Regex,
    severity: Severity,
}

/// Pattern-based payload inspector
#[derive(Default)]
pub struct PatternInspector {
    patterns: Vec<CompiledPattern>,
}

impl PatternInspector {
    /// Create a new pattern inspector from configuration
    pub fn new(config: &PatternConfig) -> anyhow::Result<Self> {
        let mut patterns = Vec::new();

        // SQL injection patterns
        if config.sqli {
            for (id, pattern) in SQL_INJECTION_PATTERNS.iter() {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        patterns.push(CompiledPattern {
                            id: format!("sqli-{}", id),
                            regex,
                            severity: Severity::High,
                        });
                    }
                    Err(e) => warn!(pattern = %id, error = %e, "Failed to compile SQLi pattern"),
                }
            }
        }

        // Command injection patterns
        if config.command_injection {
            for (id, pattern) in COMMAND_INJECTION_PATTERNS.iter() {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        patterns.push(CompiledPattern {
                            id: format!("cmd-{}", id),
                            regex,
                            severity: Severity::Critical,
                        });
                    }
                    Err(e) => warn!(pattern = %id, error = %e, "Failed to compile cmd injection pattern"),
                }
            }
        }

        // Script injection (XSS) patterns
        if config.script_injection {
            for (id, pattern) in SCRIPT_INJECTION_PATTERNS.iter() {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        patterns.push(CompiledPattern {
                            id: format!("xss-{}", id),
                            regex,
                            severity: Severity::High,
                        });
                    }
                    Err(e) => warn!(pattern = %id, error = %e, "Failed to compile XSS pattern"),
                }
            }
        }

        // Path traversal patterns
        if config.path_traversal {
            for (id, pattern) in PATH_TRAVERSAL_PATTERNS.iter() {
                match Regex::new(pattern) {
                    Ok(regex) => {
                        patterns.push(CompiledPattern {
                            id: format!("path-{}", id),
                            regex,
                            severity: Severity::High,
                        });
                    }
                    Err(e) => warn!(pattern = %id, error = %e, "Failed to compile path traversal pattern"),
                }
            }
        }

        // Custom patterns
        for custom in &config.custom_patterns {
            match Regex::new(&custom.pattern) {
                Ok(regex) => {
                    patterns.push(CompiledPattern {
                        id: format!("custom-{}", custom.name),
                        regex,
                        severity: custom.severity,
                    });
                }
                Err(e) => warn!(name = %custom.name, error = %e, "Failed to compile custom pattern"),
            }
        }

        Ok(Self { patterns })
    }

    /// Inspect text for malicious patterns
    pub fn inspect(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        for pattern in &self.patterns {
            if pattern.regex.is_match(text) {
                detections.push(Detection {
                    pattern_id: pattern.id.clone(),
                    description: format!("Matched pattern: {}", pattern.id),
                    severity: pattern.severity,
                });
            }
        }

        detections
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}


// SQL Injection patterns (simplified from WAF agent)
const SQL_INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("union-select", r"(?i)\bunion\s+(all\s+)?select\b"),
    ("or-1-1", r"(?i)\bor\s+1\s*=\s*1\b"),
    ("and-1-1", r"(?i)\band\s+1\s*=\s*1\b"),
    ("drop-table", r"(?i)\bdrop\s+table\b"),
    ("insert-into", r"(?i)\binsert\s+into\b.*\bvalues\b"),
    ("delete-from", r"(?i)\bdelete\s+from\b"),
    ("update-set", r"(?i)\bupdate\b.*\bset\b"),
    ("exec-xp", r"(?i)\bexec\s+xp_"),
    ("sleep", r"(?i)\bsleep\s*\(\s*\d+\s*\)"),
    ("benchmark", r"(?i)\bbenchmark\s*\("),
    ("having", r"(?i)\bhaving\s+\d+\s*=\s*\d+"),
    ("comment", r"(/\*|\*/|--\s)"),
];

// Command injection patterns
const COMMAND_INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("semicolon-cmd", r";\s*(ls|cat|echo|rm|wget|curl|nc|bash|sh|python|perl|ruby)\b"),
    ("pipe-cmd", r"\|\s*(ls|cat|echo|rm|wget|curl|nc|bash|sh)\b"),
    ("backtick", r"`[^`]+`"),
    ("dollar-paren", r"\$\([^)]+\)"),
    ("and-cmd", r"&&\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b"),
    ("or-cmd", r"\|\|\s*(ls|cat|rm|wget|curl|nc|bash|sh)\b"),
    ("redirect", r">\s*/etc/passwd|>\s*/tmp/"),
    ("etc-passwd", r"/etc/(passwd|shadow|group)"),
    ("dev-null", r">\s*/dev/(null|zero|random)"),
];

// Script injection (XSS) patterns
const SCRIPT_INJECTION_PATTERNS: &[(&str, &str)] = &[
    ("script-tag", r"(?i)<script[^>]*>"),
    ("script-close", r"(?i)</script\s*>"),
    ("on-event", r"(?i)\bon(error|load|click|mouse|focus|blur|change|submit)\s*="),
    ("javascript-uri", r"(?i)javascript\s*:"),
    ("vbscript-uri", r"(?i)vbscript\s*:"),
    ("data-uri", r"(?i)data\s*:[^,]*;base64"),
    ("expression", r"(?i)expression\s*\("),
    ("eval", r"(?i)\beval\s*\("),
    ("iframe", r"(?i)<iframe[^>]*>"),
    ("svg-onload", r"(?i)<svg[^>]*onload"),
];

// Path traversal patterns
const PATH_TRAVERSAL_PATTERNS: &[(&str, &str)] = &[
    ("dot-dot-slash", r"\.\./"),
    ("dot-dot-backslash", r"\.\.\\"),
    ("encoded-traversal", r"%2e%2e[/\\%]|%252e%252e"),
    ("null-byte", r"%00"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        let config = PatternConfig {
            sqli: true,
            ..Default::default()
        };
        let inspector = PatternInspector::new(&config).unwrap();

        let detections = inspector.inspect("SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords");
        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| d.pattern_id.starts_with("sqli-")));

        let detections = inspector.inspect("normal message");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_command_injection_detection() {
        let config = PatternConfig {
            command_injection: true,
            ..Default::default()
        };
        let inspector = PatternInspector::new(&config).unwrap();

        let detections = inspector.inspect("; rm -rf /");
        assert!(!detections.is_empty());

        let detections = inspector.inspect("echo `whoami`");
        assert!(!detections.is_empty());

        let detections = inspector.inspect("normal text");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_xss_detection() {
        let config = PatternConfig {
            script_injection: true,
            ..Default::default()
        };
        let inspector = PatternInspector::new(&config).unwrap();

        let detections = inspector.inspect("<script>alert('xss')</script>");
        assert!(!detections.is_empty());

        let detections = inspector.inspect("<img onerror=alert(1)>");
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_path_traversal_detection() {
        let config = PatternConfig {
            path_traversal: true,
            ..Default::default()
        };
        let inspector = PatternInspector::new(&config).unwrap();

        let detections = inspector.inspect("../../etc/passwd");
        assert!(!detections.is_empty());

        let detections = inspector.inspect("/home/user/file.txt");
        assert!(detections.is_empty());
    }

    #[test]
    fn test_custom_patterns() {
        let config = PatternConfig {
            custom_patterns: vec![
                crate::config::CustomPattern {
                    name: "secret".to_string(),
                    pattern: r"(?i)password\s*=".to_string(),
                    severity: Severity::High,
                },
            ],
            ..Default::default()
        };
        let inspector = PatternInspector::new(&config).unwrap();

        let detections = inspector.inspect("password=secret123");
        assert!(!detections.is_empty());
        assert!(detections[0].pattern_id.contains("secret"));
    }
}
