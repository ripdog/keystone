//! Authentication and authorization module
//!
//! Handles JWT-based authentication with Argon2 password hashing.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash::{PasswordHasher, SaltString}};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use keystone_core::Claims;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const TOKEN_EXPIRY_HOURS: u64 = 24;

pub struct AuthManager {
    /// The key used to sign JWTs, loaded from database
    signing_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthManager {
    /// Create a new AuthManager with a key from database
    pub fn new(key_bytes: Vec<u8>) -> Self {
        info!("Initialized AuthManager with persistent signing key");

        Self {
            signing_key: EncodingKey::from_secret(&key_bytes),
            decoding_key: DecodingKey::from_secret(&key_bytes),
        }
    }

    /// Hash a password using Argon2
    pub fn hash_password(password: &str) -> Result<String> {
        use rand::rngs::OsRng;
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
            .to_string();
        Ok(hash)
    }

    /// Verify password against hash and generate JWT token on success
    pub fn verify_and_login(&self, username: &str, input_pass: &str, stored_hash: &str) -> Result<String> {
        debug!("Attempting login for user: {}", username);

        let parsed_hash = PasswordHash::new(stored_hash)
            .map_err(|e| anyhow::anyhow!("Failed to parse stored password hash: {}", e))?;

        // Check password against Argon2 hash
        if Argon2::default()
            .verify_password(input_pass.as_bytes(), &parsed_hash)
            .is_ok()
        {
            info!("Login successful for user: {}", username);

            // Calculate expiration time
            let exp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + (TOKEN_EXPIRY_HOURS * 3600);

            let claims = Claims {
                sub: username.to_string(),
                exp,
            };

            let token = encode(&Header::default(), &claims, &self.signing_key)
                .context("Failed to generate JWT token")?;

            return Ok(token);
        }

        warn!("Login failed for user {}: invalid password", username);
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

    #[test]
    fn test_hash_and_verify() {
        let password = "test_password";
        let hash = AuthManager::hash_password(password).unwrap();
        
        // Create a dummy key for testing
        let key_bytes = vec![0u8; 32];
        let auth = AuthManager::new(key_bytes);
        
        let token = auth.verify_and_login("testuser", password, &hash);
        assert!(token.is_ok());
    }

    #[test]
    fn test_verify_invalid_password() {
        let password = "test_password";
        let hash = AuthManager::hash_password(password).unwrap();
        
        let key_bytes = vec![0u8; 32];
        let auth = AuthManager::new(key_bytes);
        
        let token = auth.verify_and_login("testuser", "wrong_password", &hash);
        assert!(token.is_err());
    }

    #[test]
    fn test_verify_valid_token() {
        let password = "test_password";
        let hash = AuthManager::hash_password(password).unwrap();
        
        let key_bytes = vec![0u8; 32];
        let auth = AuthManager::new(key_bytes);
        
        let token = auth.verify_and_login("testuser", password, &hash).unwrap();
        assert!(auth.verify(&token));
    }

    #[test]
    fn test_verify_invalid_token() {
        let key_bytes = vec![0u8; 32];
        let auth = AuthManager::new(key_bytes);
        
        assert!(!auth.verify("invalid.token.here"));
    }
}
