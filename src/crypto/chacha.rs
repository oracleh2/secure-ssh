//! ChaCha20-Poly1305 Authenticated Encryption
//!
//! ChaCha20-Poly1305 is an AEAD cipher that provides both confidentiality
//! and authenticity. It's resistant to timing attacks and performs well
//! on systems without AES hardware acceleration.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rand::rngs::OsRng;

use super::SecureBytes;
use crate::error::{Result, SecureSshError};

/// Nonce length for ChaCha20-Poly1305 (96 bits)
pub const NONCE_LEN: usize = 12;

/// Authentication tag length (128 bits)
#[allow(dead_code)]
pub const TAG_LEN: usize = 16;

/// Key length (256 bits)
pub const KEY_LEN: usize = 32;

/// Encrypt data using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Tuple of (nonce, ciphertext) where ciphertext includes the auth tag
///
/// # Security Notes
/// - Uses random nonce for each encryption
/// - Authentication tag prevents tampering
/// - Ciphertext is slightly larger than plaintext (+16 bytes for tag)
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if key.len() != KEY_LEN {
        return Err(SecureSshError::EncryptionFailed(format!(
            "Invalid key length: expected {}, got {}",
            KEY_LEN,
            key.len()
        )));
    }

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher and encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| SecureSshError::EncryptionFailed(e.to_string()))?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SecureSshError::EncryptionFailed(e.to_string()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

/// Decrypt data using ChaCha20-Poly1305
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data (includes auth tag)
///
/// # Returns
/// Decrypted plaintext wrapped in SecureBytes
///
/// # Errors
/// Returns DecryptionFailed if:
/// - Key or nonce has wrong length
/// - Authentication tag verification fails (wrong key or tampered data)
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<SecureBytes> {
    if key.len() != KEY_LEN {
        return Err(SecureSshError::DecryptionFailed);
    }

    if nonce.len() != NONCE_LEN {
        return Err(SecureSshError::DecryptionFailed);
    }

    let nonce = Nonce::from_slice(nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| SecureSshError::DecryptionFailed)?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecureSshError::DecryptionFailed)?;

    Ok(SecureBytes::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"Hello, World! This is secret data.";

        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; KEY_LEN];
        let key2 = [0x43u8; KEY_LEN];
        let plaintext = b"Secret message";

        let (nonce, ciphertext) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"Secret message";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"Same message";

        let (nonce1, ciphertext1) = encrypt(&key, plaintext).unwrap();
        let (nonce2, ciphertext2) = encrypt(&key, plaintext).unwrap();

        // Nonces should be different (random)
        assert_ne!(nonce1, nonce2);
        // Ciphertexts should be different
        assert_ne!(ciphertext1, ciphertext2);
    }
}
