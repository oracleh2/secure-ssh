//! Secure SSH - Hardware-token-style SSH client for USB flash drives
//!
//! This crate provides a secure SSH client that:
//! - Stores encrypted SSH keys on a USB flash drive
//! - Requires a master password to decrypt and use the keys
//! - Automatically disconnects when the USB drive is removed
//! - Provides resistance to reverse engineering

pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod ssh;
pub mod watchdog;

pub use error::{Result, SecureSshError};
