//! Зашифрованное хранилище ключей и конфигурации
//!
//! Формат зашифрованных файлов:
//! [4 байта: версия (u32 BE)]
//! [32 байта: соль]
//! [12 байт: nonce]
//! [N байт: шифротекст + тег аутентификации]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::crypto::{self, DerivedKey, SecureBytes, FORMAT_VERSION, HEADER_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Result, SecureSshError};

use super::ServerList;

const KEY_FILE: &str = "key.enc";
const KEY_PUB_FILE: &str = "key.pub";
const SERVERS_FILE: &str = "servers.enc";
const DATA_DIR: &str = "data";
const MARKER_FILE: &str = ".secure-ssh-marker";

/// Получить директорию исполняемого файла
pub fn get_exe_dir() -> Result<PathBuf> {
    let exe_path = std::env::current_exe()
        .map_err(SecureSshError::Io)?;

    exe_path
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| SecureSshError::Other("Не удалось определить директорию исполняемого файла".into()))
}

/// Получить путь к директории данных (относительно исполняемого файла)
pub fn get_data_dir() -> Result<PathBuf> {
    Ok(get_exe_dir()?.join(DATA_DIR))
}

/// Get the public key file path
pub fn get_public_key_path() -> Result<PathBuf> {
    Ok(get_data_dir()?.join(KEY_PUB_FILE))
}

/// Get the encrypted key file path
fn get_key_path() -> Result<PathBuf> {
    Ok(get_data_dir()?.join(KEY_FILE))
}

/// Get the servers config file path
fn get_servers_path() -> Result<PathBuf> {
    Ok(get_data_dir()?.join(SERVERS_FILE))
}

/// Check if secure-ssh is initialized (key.enc exists)
pub fn is_initialized() -> Result<bool> {
    let key_path = get_key_path()?;
    Ok(key_path.exists())
}

/// Ensure data directory exists
fn ensure_data_dir() -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }
    Ok(data_dir)
}

/// Save encrypted SSH private key
///
/// File format:
/// [4 bytes: version][32 bytes: salt][12 bytes: nonce][ciphertext][16 bytes: tag]
pub fn save_encrypted_key(
    private_key: &[u8],
    public_key_openssh: &str,
    derived_key: &DerivedKey,
) -> Result<()> {
    ensure_data_dir()?;

    // Encrypt the private key
    let (nonce, ciphertext) = crypto::encrypt(&derived_key.key, private_key)?;

    // Build the encrypted file
    let mut data = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    data.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    data.extend_from_slice(&derived_key.salt);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);

    // Write encrypted key
    let key_path = get_key_path()?;
    let mut file = File::create(&key_path)?;
    file.write_all(&data)?;
    file.sync_all()?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }

    // Write public key (plaintext)
    let pub_path = get_public_key_path()?;
    let mut pub_file = File::create(&pub_path)?;
    pub_file.write_all(public_key_openssh.as_bytes())?;
    pub_file.write_all(b"\n")?;

    Ok(())
}

/// Load and decrypt SSH private key
///
/// Returns (private_key_bytes, salt) - salt is needed for decrypting servers
pub fn load_encrypted_key(password: &[u8]) -> Result<(SecureBytes, [u8; SALT_LEN])> {
    let key_path = get_key_path()?;

    if !key_path.exists() {
        return Err(SecureSshError::NotInitialized);
    }

    // Read the encrypted file
    let mut file = File::open(&key_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < HEADER_LEN + 16 {
        // 16 = minimum ciphertext (auth tag)
        return Err(SecureSshError::InvalidConfig("Key file is corrupted".into()));
    }

    // Parse header
    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if version != FORMAT_VERSION {
        return Err(SecureSshError::InvalidConfig(format!(
            "Unsupported key file version: {}",
            version
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[4..4 + SALT_LEN]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN]);

    let ciphertext = &data[HEADER_LEN..];

    // Derive key from password using stored salt
    let derived_key = crypto::derive_key(password, Some(&salt))?;

    // Decrypt
    let private_key = crypto::decrypt(&derived_key.key, &nonce, ciphertext)?;

    Ok((private_key, salt))
}

/// Save server configurations (encrypted)
pub fn save_servers(servers: &ServerList, derived_key: &DerivedKey) -> Result<()> {
    ensure_data_dir()?;

    // Serialize to JSON
    let json = serde_json::to_vec(servers)?;

    // Encrypt
    let (nonce, ciphertext) = crypto::encrypt(&derived_key.key, &json)?;

    // Build file
    let mut data = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    data.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    data.extend_from_slice(&derived_key.salt);
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&ciphertext);

    // Write
    let path = get_servers_path()?;
    let mut file = File::create(&path)?;
    file.write_all(&data)?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Load server configurations (decrypted)
pub fn load_servers(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<ServerList> {
    let path = get_servers_path()?;

    if !path.exists() {
        // No servers configured yet - return empty list
        return Ok(ServerList::new());
    }

    // Read file
    let mut file = File::open(&path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < HEADER_LEN + 16 {
        return Err(SecureSshError::InvalidConfig("Servers file is corrupted".into()));
    }

    // Parse header
    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if version != FORMAT_VERSION {
        return Err(SecureSshError::InvalidConfig(format!(
            "Unsupported servers file version: {}",
            version
        )));
    }

    // We use the same salt as the key file for consistency
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN]);

    let ciphertext = &data[HEADER_LEN..];

    // Derive key
    let derived_key = crypto::derive_key(password, Some(salt))?;

    // Decrypt
    let plaintext = crypto::decrypt(&derived_key.key, &nonce, ciphertext)?;

    // Parse JSON
    let servers: ServerList = serde_json::from_slice(&plaintext)?;

    Ok(servers)
}

/// Прочитать публичный ключ без пароля
pub fn read_public_key() -> Result<String> {
    let path = get_public_key_path()?;

    if !path.exists() {
        return Err(SecureSshError::NotInitialized);
    }

    let content = fs::read_to_string(&path)?;
    Ok(content.trim().to_string())
}

/// Получить путь к файлу-маркеру
pub fn get_marker_path() -> Result<PathBuf> {
    Ok(get_exe_dir()?.join(MARKER_FILE))
}

/// Создать файл-маркер для watchdog
pub fn create_marker_file() -> Result<()> {
    let marker_path = get_marker_path()?;
    let mut file = File::create(&marker_path)?;
    file.write_all(b"secure-ssh marker file\n")?;
    file.write_all(b"Do not delete - used for USB detection\n")?;
    Ok(())
}

/// Проверить существование маркера
#[allow(dead_code)]
pub fn marker_exists() -> bool {
    get_marker_path().map(|p| p.exists()).unwrap_or(false)
}
