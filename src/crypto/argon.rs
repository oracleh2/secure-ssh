//! Argon2id Key Derivation Function
//!
//! Uses Argon2id (winner of the Password Hashing Competition) to derive
//! encryption keys from user passwords. Argon2id is resistant to:
//! - GPU attacks (memory-hard)
//! - Side-channel attacks (hybrid approach)
//! - Time-memory trade-off attacks

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::SecureBytes;
use crate::error::{Result, SecureSshError};

/// Salt length in bytes (256 bits)
pub const SALT_LEN: usize = 32;

/// Derived key length in bytes (256 bits for ChaCha20)
pub const KEY_LEN: usize = 32;

/// Argon2id parameters (OWASP recommended for high security)
/// - Memory: 64 MB (65536 KB)
/// - Iterations: 3
/// - Parallelism: 4 threads
const MEMORY_COST: u32 = 65536; // 64 MB
const TIME_COST: u32 = 3;
const PARALLELISM: u32 = 4;

/// A derived encryption key with its associated salt
pub struct DerivedKey {
    /// The derived key material (32 bytes)
    pub key: SecureBytes,
    /// The salt used for derivation (32 bytes)
    pub salt: [u8; SALT_LEN],
}

impl Zeroize for DerivedKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derive an encryption key from a password using Argon2id
///
/// # Arguments
/// * `password` - The user's password
/// * `salt` - Optional salt (if None, generates a new random salt)
///
/// # Returns
/// A DerivedKey containing the key material and salt
///
/// # Security Notes
/// - Uses memory-hard function to resist GPU attacks
/// - Salt prevents rainbow table attacks
/// - High iteration count slows brute-force attempts
pub fn derive_key(password: &[u8], salt: Option<&[u8; SALT_LEN]>) -> Result<DerivedKey> {
    // Generate or use provided salt
    let salt_bytes: [u8; SALT_LEN] = match salt {
        Some(s) => *s,
        None => {
            let mut s = [0u8; SALT_LEN];
            use rand::RngCore;
            OsRng.fill_bytes(&mut s);
            s
        }
    };

    // Configure Argon2id with secure parameters
    let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN))
        .map_err(|e| SecureSshError::Other(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Derive the key
    let mut key_bytes = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password, &salt_bytes, &mut key_bytes)
        .map_err(|e| SecureSshError::Other(format!("Key derivation failed: {}", e)))?;

    Ok(DerivedKey {
        key: SecureBytes::new(key_bytes),
        salt: salt_bytes,
    })
}

/// Derive a key using an existing salt (for decryption)
#[allow(dead_code)]
pub fn derive_key_with_salt(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<DerivedKey> {
    derive_key(password, Some(salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test_password_123";
        let salt = [0x42u8; SALT_LEN];

        let key1 = derive_key(password, Some(&salt)).unwrap();
        let key2 = derive_key(password, Some(&salt)).unwrap();

        assert_eq!(&*key1.key, &*key2.key);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"test_password_123";
        let salt1 = [0x42u8; SALT_LEN];
        let salt2 = [0x43u8; SALT_LEN];

        let key1 = derive_key(password, Some(&salt1)).unwrap();
        let key2 = derive_key(password, Some(&salt2)).unwrap();

        assert_ne!(&*key1.key, &*key2.key);
    }

    #[test]
    fn test_derive_key_random_salt() {
        let password = b"test_password_123";

        let key1 = derive_key(password, None).unwrap();
        let key2 = derive_key(password, None).unwrap();

        // Different random salts should produce different keys
        assert_ne!(key1.salt, key2.salt);
        assert_ne!(&*key1.key, &*key2.key);
    }
}
