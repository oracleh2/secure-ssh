//! Cryptographic primitives for secure-ssh
//!
//! This module provides:
//! - Argon2id for password-based key derivation
//! - ChaCha20-Poly1305 for authenticated encryption
//! - Ed25519 for SSH key generation
//! - Secure memory handling with automatic zeroing

mod argon;
mod chacha;
mod keys;
mod secure_bytes;

pub use argon::{derive_key, DerivedKey, SALT_LEN};
pub use chacha::{decrypt, encrypt, NONCE_LEN};
#[allow(unused_imports)]
pub use keys::{generate_keypair, KeyPair};
pub use secure_bytes::SecureBytes;

/// Current version of the encrypted file format
pub const FORMAT_VERSION: u32 = 1;

/// File header structure:
/// [4 bytes: version][32 bytes: salt][12 bytes: nonce][N bytes: ciphertext][16 bytes: tag]
pub const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN;
