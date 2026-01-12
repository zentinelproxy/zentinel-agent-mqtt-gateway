//! JWT-based authentication
//!
//! Validates JWT tokens passed in the MQTT password field.

use super::{AuthResult, AuthenticatorProvider};
use crate::mqtt::ParsedConnect;
use anyhow::Result;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (usually user ID)
    pub sub: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<StringOrVec>,
    /// Expiration time (Unix timestamp)
    pub exp: Option<u64>,
    /// Issued at (Unix timestamp)
    pub iat: Option<u64>,
    /// Not before (Unix timestamp)
    pub nbf: Option<u64>,
    /// User groups
    pub groups: Option<Vec<String>>,
    /// Username claim (configurable)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// String or array of strings (for audience claim)
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    pub fn contains(&self, s: &str) -> bool {
        match self {
            Self::String(v) => v == s,
            Self::Vec(v) => v.iter().any(|x| x == s),
        }
    }
}

/// JWT authenticator
pub struct JwtAuthenticator {
    /// Expected issuer (optional)
    issuer: Option<String>,
    /// Expected audience (optional)
    audience: Option<String>,
    /// Secret key for HMAC algorithms
    secret: Option<String>,
    /// Claim to use as username
    username_claim: String,
}

impl JwtAuthenticator {
    pub fn new(
        issuer: Option<String>,
        audience: Option<String>,
        secret: Option<String>,
        username_claim: String,
    ) -> Self {
        Self {
            issuer,
            audience,
            secret,
            username_claim,
        }
    }

    fn extract_username(&self, claims: &Claims) -> Option<String> {
        // First try the configured claim
        if self.username_claim == "sub" {
            return claims.sub.clone();
        }

        // Check extra claims
        claims.extra.get(&self.username_claim).and_then(|v| {
            match v {
                serde_json::Value::String(s) => Some(s.clone()),
                _ => None,
            }
        })
    }
}

impl AuthenticatorProvider for JwtAuthenticator {
    fn authenticate(&self, connect: &ParsedConnect, _client_ip: &str) -> Result<AuthResult> {
        // JWT is expected in the password field
        let token = match &connect.password {
            Some(p) => match String::from_utf8(p.clone()) {
                Ok(t) => t,
                Err(_) => return Ok(AuthResult::failure("Invalid token encoding")),
            },
            None => return Ok(AuthResult::failure("No token provided")),
        };

        // Get decoding key
        let key = match &self.secret {
            Some(secret) => DecodingKey::from_secret(secret.as_bytes()),
            None => {
                // Without a secret or JWKS, we can't validate
                return Ok(AuthResult::failure("No secret configured for JWT validation"));
            }
        };

        // Build validation
        let mut validation = Validation::new(Algorithm::HS256);

        // Configure issuer validation
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        } else {
            // No issuer configured, skip issuer validation
            validation.iss = None;
        }

        // Configure audience validation
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        } else {
            // No audience configured, skip audience validation
            validation.aud = None;
        }

        // Decode and validate token
        let token_data = match decode::<Claims>(&token, &key, &validation) {
            Ok(data) => data,
            Err(e) => {
                return Ok(AuthResult::failure(&format!("Token validation failed: {}", e)));
            }
        };

        let claims = token_data.claims;

        // Extract username
        let username = self.extract_username(&claims);

        // Extract groups
        let groups = claims.groups.unwrap_or_default();

        // Build attributes from extra claims
        let mut attributes = HashMap::new();
        for (key, value) in &claims.extra {
            if let serde_json::Value::String(s) = value {
                attributes.insert(key.clone(), s.clone());
            }
        }

        let mut result = AuthResult::success(username, groups);
        result.attributes = attributes;

        Ok(result)
    }

    fn name(&self) -> &str {
        "jwt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::HashMap;

    fn create_test_token(claims: &Claims, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_jwt() {
        let secret = "test-secret-key";
        let auth = JwtAuthenticator::new(
            Some("test-issuer".to_string()),
            None,
            Some(secret.to_string()),
            "sub".to_string(),
        );

        let claims = Claims {
            sub: Some("user123".to_string()),
            iss: Some("test-issuer".to_string()),
            aud: None,
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: Some(chrono::Utc::now().timestamp() as u64),
            nbf: None,
            groups: Some(vec!["admin".to_string()]),
            extra: HashMap::new(),
        };

        let token = create_test_token(&claims, secret);

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: Some("user123".to_string()),
            password: Some(token.into_bytes()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(result.authenticated);
        assert_eq!(result.username, Some("user123".to_string()));
        assert!(result.groups.contains(&"admin".to_string()));
    }

    #[test]
    fn test_expired_jwt() {
        let secret = "test-secret-key";
        let auth = JwtAuthenticator::new(None, None, Some(secret.to_string()), "sub".to_string());

        let claims = Claims {
            sub: Some("user123".to_string()),
            iss: None,
            aud: None,
            exp: Some(chrono::Utc::now().timestamp() as u64 - 3600), // Expired
            iat: None,
            nbf: None,
            groups: None,
            extra: HashMap::new(),
        };

        let token = create_test_token(&claims, secret);

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: Some(token.into_bytes()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(!result.authenticated);
        assert!(result.reason.unwrap().contains("Token validation failed"));
    }

    #[test]
    fn test_invalid_signature() {
        let auth = JwtAuthenticator::new(
            None,
            None,
            Some("correct-secret".to_string()),
            "sub".to_string(),
        );

        let claims = Claims {
            sub: Some("user123".to_string()),
            iss: None,
            aud: None,
            exp: Some(chrono::Utc::now().timestamp() as u64 + 3600),
            iat: None,
            nbf: None,
            groups: None,
            extra: HashMap::new(),
        };

        // Token signed with different secret
        let token = create_test_token(&claims, "wrong-secret");

        let connect = ParsedConnect {
            protocol_version: 4,
            client_id: "client1".to_string(),
            clean_session: true,
            keep_alive: 60,
            username: None,
            password: Some(token.into_bytes()),
            will_topic: None,
            will_payload: None,
            will_qos: 0,
            will_retain: false,
        };

        let result = auth.authenticate(&connect, "127.0.0.1").unwrap();
        assert!(!result.authenticated);
    }
}
