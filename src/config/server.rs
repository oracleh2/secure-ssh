//! Server configuration structures

use serde::{Deserialize, Serialize};

/// A single server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Unique name for this server (e.g., "main", "backup")
    pub name: String,
    /// Hostname or IP address
    pub host: String,
    /// SSH port (default: 22)
    pub port: u16,
    /// Username for SSH connection
    pub user: String,
    /// Optional description
    #[serde(default)]
    pub description: String,
}

impl Server {
    /// Create a new server configuration
    pub fn new(name: impl Into<String>, host: impl Into<String>, port: u16, user: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            user: user.into(),
            description: String::new(),
        }
    }

    /// Create with description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Get the SSH connection string (user@host:port)
    pub fn connection_string(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            name: "main".to_string(),
            host: "localhost".to_string(),
            port: 22,
            user: "root".to_string(),
            description: String::new(),
        }
    }
}

/// A list of server configurations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerList {
    pub servers: Vec<Server>,
}

impl ServerList {
    /// Create an empty server list
    pub fn new() -> Self {
        Self { servers: Vec::new() }
    }

    /// Add a server to the list
    pub fn add(&mut self, server: Server) -> Result<(), &'static str> {
        if self.servers.iter().any(|s| s.name == server.name) {
            return Err("Server with this name already exists");
        }
        self.servers.push(server);
        Ok(())
    }

    /// Remove a server by name
    pub fn remove(&mut self, name: &str) -> Option<Server> {
        if let Some(pos) = self.servers.iter().position(|s| s.name == name) {
            Some(self.servers.remove(pos))
        } else {
            None
        }
    }

    /// Get a server by name
    pub fn get(&self, name: &str) -> Option<&Server> {
        self.servers.iter().find(|s| s.name == name)
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Get the number of servers
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Get the first server (useful when only one is configured)
    pub fn first(&self) -> Option<&Server> {
        self.servers.first()
    }

    /// Iterate over servers
    pub fn iter(&self) -> impl Iterator<Item = &Server> {
        self.servers.iter()
    }
}
