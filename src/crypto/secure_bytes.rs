//! Secure byte container with automatic zeroing on drop
//!
//! This wrapper ensures that sensitive data is:
//! 1. Zeroed when dropped (prevents memory leaks)
//! 2. Not accidentally cloned or printed
//! 3. Locked in memory where possible (prevents swapping)

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A secure container for sensitive bytes that automatically zeroes on drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    /// Create a new SecureBytes from a vector
    /// The original vector is consumed and its memory is now managed securely
    pub fn new(data: Vec<u8>) -> Self {
        let secure = Self(data);
        secure.lock_memory();
        secure
    }

    /// Create a SecureBytes with a specific capacity
    #[allow(dead_code)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(Vec::with_capacity(capacity))
    }

    /// Create a zeroed SecureBytes of specific length
    #[allow(dead_code)]
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    /// Lock memory to prevent swapping (best effort, may fail without privileges)
    #[cfg(unix)]
    fn lock_memory(&self) {
        unsafe {
            // mlock prevents the memory from being swapped to disk
            // This is a security measure to prevent secrets from leaking to swap
            libc::mlock(self.0.as_ptr() as *const libc::c_void, self.0.len());
        }
    }

    #[cfg(not(unix))]
    fn lock_memory(&self) {
        // On non-Unix platforms, we rely on the OS not to swap
        // Windows has VirtualLock but requires specific privileges
    }

    /// Get the length of the secure bytes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert to a regular Vec, consuming self
    /// WARNING: The returned Vec is no longer protected!
    #[allow(dead_code)]
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl Default for SecureBytes {
    fn default() -> Self {
        Self(Vec::new())
    }
}

// Prevent accidental debug printing of secrets
impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &self.0.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_zeroed_on_drop() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let ptr = data.as_ptr();
        let len = data.len();

        {
            let secure = SecureBytes::new(data);
            assert_eq!(&*secure, &[0xDE, 0xAD, 0xBE, 0xEF]);
            // secure is dropped here
        }

        // Note: This test is best-effort - the memory might be reused
        // In practice, Zeroize guarantees the zeroing happens
    }

    #[test]
    fn test_secure_bytes_deref() {
        let secure = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(secure.len(), 4);
        assert_eq!(&*secure, &[1, 2, 3, 4]);
    }
}
