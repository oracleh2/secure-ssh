//! Ed25519 SSH Key Generation
//!
//! Ed25519 is a modern elliptic curve signature algorithm that provides:
//! - Strong security (128-bit security level)
//! - Small key sizes (32 bytes private, 32 bytes public)
//! - Fast signature generation and verification
//! - Resistance to many side-channel attacks

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::SecureBytes;
use crate::error::{Result, SecureSshError};

/// An Ed25519 keypair with secure memory handling
pub struct KeyPair {
    /// Private key (32 bytes) - kept in secure memory
    private_key: SecureBytes,
    /// Public key (32 bytes)
    public_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a new random Ed25519 keypair
    pub fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        Ok(Self {
            private_key: SecureBytes::new(signing_key.to_bytes().to_vec()),
            public_key: verifying_key.to_bytes().to_vec(),
        })
    }

    /// Create a KeyPair from an existing private key
    pub fn from_private_key(private_key: SecureBytes) -> Result<Self> {
        if private_key.len() != 32 {
            return Err(SecureSshError::KeyGenerationFailed(
                "Invalid private key length".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&private_key);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();

        // Zeroize the temporary array
        key_bytes.zeroize();

        Ok(Self {
            private_key,
            public_key: verifying_key.to_bytes().to_vec(),
        })
    }

    /// Get the private key bytes (for encryption/storage)
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// Get the public key bytes
    #[allow(dead_code)]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the public key in OpenSSH format
    /// Format: "ssh-ed25519 <base64-encoded-key> <comment>"
    pub fn public_key_openssh(&self, comment: &str) -> String {
        // OpenSSH format for Ed25519:
        // [4 bytes: length of "ssh-ed25519"][11 bytes: "ssh-ed25519"]
        // [4 bytes: length of key][32 bytes: public key]
        let key_type = b"ssh-ed25519";
        let mut blob = Vec::new();

        // Add key type length and value
        blob.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        blob.extend_from_slice(key_type);

        // Add public key length and value
        blob.extend_from_slice(&(self.public_key.len() as u32).to_be_bytes());
        blob.extend_from_slice(&self.public_key);

        // Base64 encode
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let encoded = STANDARD.encode(&blob);

        format!("ssh-ed25519 {} {}", encoded, comment)
    }

    /// Consume the keypair and return the private key
    /// Uses mem::take to safely extract the private key while still running Drop
    #[allow(dead_code)]
    pub fn into_private_key(mut self) -> SecureBytes {
        std::mem::take(&mut self.private_key)
    }
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generate a new Ed25519 keypair
#[allow(dead_code)]
pub fn generate_keypair() -> Result<KeyPair> {
    KeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair().unwrap();

        assert_eq!(keypair.private_key_bytes().len(), 32);
        assert_eq!(keypair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_keypair_from_private_key() {
        let original = generate_keypair().unwrap();
        let private_bytes = SecureBytes::new(original.private_key_bytes().to_vec());
        let original_public = original.public_key_bytes().to_vec();

        let restored = KeyPair::from_private_key(private_bytes).unwrap();

        assert_eq!(restored.public_key_bytes(), &original_public);
    }

    #[test]
    fn test_public_key_openssh_format() {
        let keypair = generate_keypair().unwrap();
        let openssh = keypair.public_key_openssh("test-comment");

        assert!(openssh.starts_with("ssh-ed25519 "));
        assert!(openssh.ends_with(" test-comment"));
    }
}

// Need to add base64 to Cargo.toml - let me note this
