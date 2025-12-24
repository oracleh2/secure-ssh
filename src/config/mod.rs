//! Configuration management for secure-ssh
//!
//! Handles encrypted storage of:
//! - SSH private key
//! - Server configurations

mod server;
mod storage;

pub use server::{Server, ServerList};
#[allow(unused_imports)]
pub use storage::{
    load_encrypted_key, load_servers, save_encrypted_key, save_servers,
    get_data_dir, get_public_key_path, is_initialized, read_public_key,
    get_exe_dir, get_marker_path, create_marker_file, marker_exists,
};
