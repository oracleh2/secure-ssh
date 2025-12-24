//! SSH client handler

use std::sync::Arc;
use async_trait::async_trait;
use russh::client::{self, Msg};
use russh::{Channel, ChannelId};
use russh_keys::key::PublicKey;

use crate::error::{Result, SecureSshError};

/// SSH client handler
pub struct SshClient;

impl SshClient {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl client::Handler for SshClient {
    type Error = russh::Error;

    /// Called when server sends its public key for verification
    /// In a production system, you should verify against known_hosts
    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // TODO: Implement proper host key verification
        // For now, accept all keys (like ssh with StrictHostKeyChecking=no)
        // This should be improved in production!
        Ok(true)
    }

    /// Called when data is received on a channel
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Write received data to stdout
        use std::io::Write;
        std::io::stdout().write_all(data).ok();
        std::io::stdout().flush().ok();
        Ok(())
    }

    /// Called when extended data (stderr) is received
    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _ext: u32,
        data: &[u8],
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Write stderr data
        use std::io::Write;
        std::io::stderr().write_all(data).ok();
        std::io::stderr().flush().ok();
        Ok(())
    }
}

/// Connect to an SSH server using Ed25519 key
pub async fn connect(
    host: &str,
    port: u16,
    user: &str,
    private_key_bytes: &[u8],
) -> Result<(client::Handle<SshClient>, Channel<Msg>)> {
    // For Ed25519, the private key is 32 bytes (seed)
    if private_key_bytes.len() != 32 {
        return Err(SecureSshError::InvalidConfig(format!(
            "Invalid private key length: expected 32, got {}",
            private_key_bytes.len()
        )));
    }

    // Create ed25519_dalek signing key from bytes
    let key_bytes: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
        SecureSshError::KeyGenerationFailed("Invalid key bytes".into())
    })?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    // Convert to russh_keys format
    // russh_keys 0.45 uses its own key types
    let keypair = russh_keys::key::KeyPair::Ed25519(signing_key);

    // SSH client configuration
    let config = client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    };

    let config = Arc::new(config);
    let handler = SshClient::new();

    // Connect to the server
    let addr = format!("{}:{}", host, port);
    let mut session = client::connect(config, addr, handler)
        .await
        .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;

    // Authenticate with our key
    let auth_result = session
        .authenticate_publickey(user, Arc::new(keypair))
        .await
        .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;

    if !auth_result {
        return Err(SecureSshError::SshAuthFailed);
    }

    // Open a session channel
    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;

    Ok((session, channel))
}
