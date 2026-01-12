//! File-based username/password authentication

use super::{AuthResult, AuthenticatorProvider};
use crate::mqtt::ParsedConnect;
use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// User entry in credentials file
#[derive(Debug, Clone, Deserialize)]
pub struct UserEntry {
    /// Bcrypt hashed password
    pub password_hash: String,
    /// User groups for ACL
    #[serde(default)]
    pub groups: Vec<String>,
    /// Whether user is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Additional attributes
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Credentials file format
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialsFile {
    /// Map of username to user entry
    pub users: HashMap<String, UserEntry>,
}

/// File-based credentials authenticator
pub struct CredentialsAuthenticator {
    /// Path to credentials file
    path: PathBuf,
    /// Cached users
    users: Arc<RwLock<HashMap<String, UserEntry>>>,
    /// Hot reload on every check
    hot_reload: bool,
}

impl CredentialsAuthenticator {
    /// Create from a credentials file
    pub fn from_file(path: &Path, hot_reload: bool) -> Result<Self> {
        let users = load_credentials_file(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            users: Arc::new(RwLock::new(users)),
            hot_reload,
        })
    }

    /// Reload credentials from file
    pub fn reload(&self) -> Result<()> {
        let users = load_credentials_file(&self.path)?;
        *self.users.write() = users;
        Ok(())
    }

    /// Add or update a user (for programmatic use)
    pub fn set_user(&self, username: &str, entry: UserEntry) {
        self.users.write().insert(username.to_string(), entry);
    }

    /// Remove a user
    pub fn remove_user(&self, username: &str) -> bool {
        self.users.write().remove(username).is_some()
    }

    /// Get user count
    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }
}

impl AuthenticatorProvider for CredentialsAuthenticator {
    fn authenticate(&self, connect: &ParsedConnect, _client_ip: &str) -> Result<AuthResult> {
        // Hot reload if configured
        if self.hot_reload {
            if let Err(e) = self.reload() {
                tracing::warn!(error = %e, "Failed to hot reload credentials file");
            }
        }

        let username = match &connect.username {
            Some(u) => u,
            None => return Ok(AuthResult::failure("No username provided")),
        };

        let password = match &connect.password {
            Some(p) => p,
            None => return Ok(AuthResult::failure("No password provided")),
        };

        let users = self.users.read();
        let user = match users.get(username) {
            Some(u) => u,
            None => return Ok(AuthResult::failure("User not found")),
        };

        // Check if user is enabled
        if !user.enabled {
            return Ok(AuthResult::failure("User is disabled"));
        }

        // Verify password
        match bcrypt::verify(password, &user.password_hash) {
            Ok(true) => {
                let mut result = AuthResult::success(Some(username.clone()), user.groups.clone());
                result.attributes = user.attributes.clone();
                Ok(result)
            }
            Ok(false) => Ok(AuthResult::failure("Invalid password")),
            Err(e) => {
                tracing::warn!(error = %e, "Password verification error");
                Ok(AuthResult::failure("Password verification error"))
            }
        }
    }

    fn name(&self) -> &str {
        "credentials-file"
    }
}

fn load_credentials_file(path: &Path) -> Result<HashMap<String, UserEntry>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read credentials file: {}", path.display()))?;

    // Try JSON first, then YAML
    let file: CredentialsFile = if path.extension().map(|e| e == "json").unwrap_or(false) {
        serde_json::from_str(&contents)
            .with_context(|| "Failed to parse JSON credentials file")?
    } else {
        // Assume YAML
        serde_json::from_str(&contents)
            .or_else(|_| {
                // If JSON fails, content might be YAML-like but we only have serde_json
                // In production, you'd use serde_yaml here
                Err(anyhow::anyhow!("YAML parsing requires serde_yaml"))
            })
            .with_context(|| "Failed to parse credentials file")?
    };

    Ok(file.users)
}

/// Hash a password for storage
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .context("Failed to hash password")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_credentials() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();

        // Hash "password123"
        let hash = bcrypt::hash("password123", 4).unwrap();

        let content = format!(
            r#"{{
                "users": {{
                    "testuser": {{
                        "password_hash": "{}",
                        "groups": ["users", "sensors"],
                        "enabled": true
                    }},
                    "disabled": {{
                        "password_hash": "{}",
                        "groups": [],
                        "enabled": false
                    }}
                }}
            }}"#,
            hash, hash
        );

        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_successful_auth() {
        let file = create_test_credentials();
        let auth = CredentialsAuthenticator::from_file(file.path(), false).unwrap();

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: Some("testuser".to_string()),
            password: Some(b"password123".to_vec()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(result.authenticated);
        assert_eq!(result.username, Some("testuser".to_string()));
        assert!(result.groups.contains(&"sensors".to_string()));
    }

    #[test]
    fn test_wrong_password() {
        let file = create_test_credentials();
        let auth = CredentialsAuthenticator::from_file(file.path(), false).unwrap();

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: Some("testuser".to_string()),
            password: Some(b"wrongpassword".to_vec()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(!result.authenticated);
    }

    #[test]
    fn test_disabled_user() {
        let file = create_test_credentials();
        let auth = CredentialsAuthenticator::from_file(file.path(), false).unwrap();

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: Some("disabled".to_string()),
            password: Some(b"password123".to_vec()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(!result.authenticated);
        assert_eq!(result.reason, Some("User is disabled".to_string()));
    }
}
