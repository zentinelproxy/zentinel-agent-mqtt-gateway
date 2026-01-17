//! Authentication module
//!
//! Provides various authentication mechanisms for MQTT clients.

mod credentials;
mod jwt;

pub use credentials::CredentialsAuthenticator;
pub use jwt::JwtAuthenticator;

use crate::config::{AuthConfig, AuthProvider, ConnectionContext};
use crate::mqtt::ParsedConnect;
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, warn};

/// Result of authentication
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Whether authentication succeeded
    pub authenticated: bool,
    /// Username (may be extracted from token or cert)
    pub username: Option<String>,
    /// User groups for ACL
    pub groups: Vec<String>,
    /// Additional attributes
    pub attributes: std::collections::HashMap<String, String>,
    /// Reason for failure (if not authenticated)
    pub reason: Option<String>,
}

impl AuthResult {
    pub fn success(username: Option<String>, groups: Vec<String>) -> Self {
        Self {
            authenticated: true,
            username,
            groups,
            attributes: Default::default(),
            reason: None,
        }
    }

    pub fn anonymous() -> Self {
        Self {
            authenticated: true,
            username: None,
            groups: vec!["anonymous".to_string()],
            attributes: Default::default(),
            reason: None,
        }
    }

    pub fn failure(reason: &str) -> Self {
        Self {
            authenticated: false,
            username: None,
            groups: Vec::new(),
            attributes: Default::default(),
            reason: Some(reason.to_string()),
        }
    }
}

/// Authentication provider trait
pub trait AuthenticatorProvider: Send + Sync {
    /// Authenticate using CONNECT packet credentials
    fn authenticate(&self, connect: &ParsedConnect, client_ip: &str) -> Result<AuthResult>;

    /// Provider name for logging
    fn name(&self) -> &str;
}

/// Multi-provider authenticator
#[derive(Default)]
pub struct Authenticator {
    providers: Vec<Arc<dyn AuthenticatorProvider>>,
    #[allow(clippy::derivable_impls)]
    config: AuthConfig,
}

impl Authenticator {
    /// Create a new authenticator from configuration
    pub fn new(config: &AuthConfig) -> Result<Self> {
        let mut providers: Vec<Arc<dyn AuthenticatorProvider>> = Vec::new();

        for provider_config in &config.providers {
            match provider_config {
                AuthProvider::File { path, hot_reload } => {
                    let auth = CredentialsAuthenticator::from_file(path, *hot_reload)?;
                    providers.push(Arc::new(auth));
                }
                AuthProvider::Jwt {
                    issuer,
                    audience,
                    secret,
                    username_claim,
                    ..
                } => {
                    let auth = JwtAuthenticator::new(
                        issuer.clone(),
                        audience.clone(),
                        secret.clone(),
                        username_claim.clone(),
                    );
                    providers.push(Arc::new(auth));
                }
                AuthProvider::Http { .. } => {
                    // HTTP auth would require async - simplified for now
                    warn!("HTTP authentication provider not yet implemented");
                }
                AuthProvider::Certificate { .. } => {
                    // Certificate auth requires TLS context from proxy
                    debug!("Certificate auth configured - requires mTLS context from proxy");
                }
            }
        }

        Ok(Self {
            providers,
            config: config.clone(),
        })
    }

    /// Authenticate a CONNECT packet
    pub fn authenticate(&self, connect: &ParsedConnect, client_ip: &str) -> AuthResult {
        // If authentication is disabled, allow everything
        if !self.config.enabled {
            return AuthResult::success(connect.username.clone(), vec![]);
        }

        // Check for anonymous connection
        if connect.username.is_none() && connect.password.is_none() {
            if self.config.allow_anonymous {
                debug!(client_id = %connect.client_id, "Anonymous connection allowed");
                return AuthResult::anonymous();
            } else {
                return AuthResult::failure("Anonymous connections not allowed");
            }
        }

        // Validate client ID if pattern is configured
        if let Some(ref pattern) = self.config.client_id_pattern {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if !regex.is_match(&connect.client_id) {
                    return AuthResult::failure("Client ID does not match required pattern");
                }
            }
        }

        // Check client ID length
        if connect.client_id.len() < self.config.min_client_id_length {
            return AuthResult::failure("Client ID too short");
        }
        if connect.client_id.len() > self.config.max_client_id_length {
            return AuthResult::failure("Client ID too long");
        }

        // Try each provider in order
        for provider in &self.providers {
            match provider.authenticate(connect, client_ip) {
                Ok(result) if result.authenticated => {
                    debug!(
                        provider = %provider.name(),
                        username = ?result.username,
                        client_id = %connect.client_id,
                        "Authentication successful"
                    );
                    return result;
                }
                Ok(result) => {
                    debug!(
                        provider = %provider.name(),
                        reason = ?result.reason,
                        "Authentication failed, trying next provider"
                    );
                }
                Err(e) => {
                    warn!(
                        provider = %provider.name(),
                        error = %e,
                        "Authentication provider error"
                    );
                }
            }
        }

        // No provider authenticated the user
        AuthResult::failure("Authentication failed")
    }

    /// Update context with authentication result
    pub fn apply_to_context(&self, context: &mut ConnectionContext, result: &AuthResult) {
        if result.authenticated {
            if let Some(ref username) = result.username {
                context.username = Some(username.clone());
            }
            context.groups = result.groups.clone();
            context.attributes = result.attributes.clone();
        }
    }

    /// Reconfigure with new settings
    pub fn reconfigure(&mut self, config: &AuthConfig) -> Result<()> {
        *self = Self::new(config)?;
        Ok(())
    }
}

