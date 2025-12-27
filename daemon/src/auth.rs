//! Authentication and authorization module
//!
//! Handles JWT-based authentication with Argon2 password hashing.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use keystone_core::Claims;
use rand::random;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const TOKEN_EXPIRY_HOURS: u64 = 24;

pub struct AuthManager {
    /// The key used to sign JWTs. Ephemeral (lost on restart).
    signing_key: EncodingKey,
    decoding_key: DecodingKey,
    /// The admin password hash loaded from disk
    admin_hash: String,
}

impl AuthManager {
    /// Create a new AuthManager with an ephemeral signing key
    pub fn new(password_hash: String) -> Self {
        // Generate a random key for this session
        let secret: [u8; 32] = random();

        info!("Initialized AuthManager with ephemeral signing key");

        Self {
            signing_key: EncodingKey::from_secret(&secret),
            decoding_key: DecodingKey::from_secret(&secret),
            admin_hash: password_hash,
        }
    }

    /// Verify password and generate JWT token on success
    pub fn login(&self, input_pass: &str) -> Result<String> {
        debug!("Attempting login");

        let parsed_hash = PasswordHash::new(&self.admin_hash)
            .map_err(|e| anyhow::anyhow!("Failed to parse stored password hash: {}", e))?;

        // Check password against Argon2 hash
        if Argon2::default()
            .verify_password(input_pass.as_bytes(), &parsed_hash)
            .is_ok()
        {
            info!("Login successful");

            // Calculate expiration time
            let exp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + (TOKEN_EXPIRY_HOURS * 3600);

            let claims = Claims {
                sub: "admin".to_string(),
                exp,
            };

            let token = encode(&Header::default(), &claims, &self.signing_key)
                .context("Failed to generate JWT token")?;

            return Ok(token);
        }

        warn!("Login failed: invalid password");
        anyhow::bail!("Invalid password")
    }

    /// Verify a JWT token's validity
    pub fn verify(&self, token: &str) -> bool {
        match decode::<Claims>(token, &self.decoding_key, &Validation::default()) {
            Ok(_) => {
                debug!("Token verified successfully");
                true
            }
            Err(e) => {
                warn!("Token verification failed: {}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand::rngs::OsRng;

    #[test]
    fn test_login_success() {
        // Create a test password hash
        let password = "test_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let auth = AuthManager::new(hash);
        let token = auth.login(password);

        assert!(token.is_ok());
    }

    #[test]
    fn test_login_failure() {
        let password = "test_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let auth = AuthManager::new(hash);
        let token = auth.login("wrong_password");

        assert!(token.is_err());
    }

    #[test]
    fn test_verify_valid_token() {
        let password = "test_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let auth = AuthManager::new(hash);
        let token = auth.login(password).unwrap();

        assert!(auth.verify(&token));
    }

    #[test]
    fn test_verify_invalid_token() {
        let password = "test_password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let auth = AuthManager::new(hash);

        assert!(!auth.verify("invalid.token.here"));
    }
}
