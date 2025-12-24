# Secure-SSH

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

**Hardware-token-style secure SSH client with encrypted key storage**

[Русская версия (Russian)](README_RU.md)

---

## Overview

Secure-SSH is a command-line SSH client designed to work like a hardware security token. It stores your SSH private key encrypted on a USB drive, requiring a master password to decrypt and use it. When the USB drive is removed, all active connections are automatically terminated.

### Key Features

- **Military-grade encryption**: Argon2id + ChaCha20-Poly1305
- **Ed25519 SSH keys**: Modern, secure, and fast
- **USB watchdog**: Auto-disconnect when USB drive is removed
- **Secure memory handling**: Keys are zeroed on drop, memory locked to prevent swapping
- **Cross-platform**: Linux, Windows, macOS (x86_64 and ARM64)
- **Portable**: Single binary, no installation required
- **No GUI**: Command-line interface for maximum security

---

## Table of Contents

- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Usage](#usage)
- [Commands Reference](#commands-reference)
- [How It Works](#how-it-works)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## Security Architecture

### Encryption Stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Derivation | **Argon2id** | Password → Encryption Key |
| Symmetric Encryption | **ChaCha20-Poly1305** | Encrypt private key & configs |
| SSH Keys | **Ed25519** | Authentication with servers |

### Argon2id Parameters (OWASP Recommended)

- Memory: 64 MB
- Iterations: 3
- Parallelism: 4 threads
- Salt: 256-bit random

### Memory Protection

- Private keys stored in `SecureBytes` wrapper
- Automatic zeroing on drop via `zeroize` crate
- Memory locking via `mlock()` to prevent swapping
- No key material in logs or debug output

---

## Installation

### Pre-built Binaries

Download the latest release for your platform:

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `secure-ssh` |
| Windows x86_64 | `secure-ssh.exe` |
| macOS x86_64 | `secure-ssh` |
| macOS ARM64 (Apple Silicon) | `secure-ssh` |

### From Source

See [Building from Source](#building-from-source) section below.

---

## Building from Source

### Prerequisites

1. **Rust toolchain** (1.75 or later)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

2. **For cross-compilation (optional)**

```bash
# Windows target
sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu

# macOS targets (requires Zig)
cargo install cargo-zigbuild
rustup target add x86_64-apple-darwin aarch64-apple-darwin

# Install Zig (for macOS cross-compilation)
# Download from https://ziglang.org/download/
```

### Build Commands

#### Linux (native)

```bash
git clone https://github.com/oracleh2/secure-ssh.git
cd secure-ssh
cargo build --release
```

Binary location: `target/release/secure-ssh`

#### Windows (cross-compile from Linux)

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Binary location: `target/x86_64-pc-windows-gnu/release/secure-ssh.exe`

#### macOS (cross-compile from Linux)

```bash
# Intel Mac
cargo zigbuild --release --target x86_64-apple-darwin

# Apple Silicon
cargo zigbuild --release --target aarch64-apple-darwin
```

Binary locations:
- `target/x86_64-apple-darwin/release/secure-ssh`
- `target/aarch64-apple-darwin/release/secure-ssh`

#### Build All Platforms

```bash
./build-all.sh
```

### Build Optimization

The release build includes:
- LTO (Link-Time Optimization)
- Single codegen unit
- Symbol stripping
- Panic = abort

Resulting binary size: ~2 MB

---

## Usage

### Quick Start

1. **Copy the binary to your USB drive**

```bash
cp target/release/secure-ssh /media/your-usb-drive/
cd /media/your-usb-drive/
```

2. **Initialize with a master password**

```bash
./secure-ssh init
```

This will:
- Create a new Ed25519 SSH key pair
- Encrypt the private key with your master password
- Create a marker file for USB detection
- Display your public key

3. **Add your public key to a server**

```bash
./secure-ssh pubkey
# Copy the output to ~/.ssh/authorized_keys on your server
```

4. **Add a server configuration**

```bash
./secure-ssh server add
```

5. **Connect to a server**

```bash
./secure-ssh connect
# or
./secure-ssh connect myserver
```

---

## Commands Reference

### `secure-ssh init`

Initialize secure-ssh with a new master password and SSH key pair.

```bash
./secure-ssh init
```

**What it does:**
- Generates a new Ed25519 key pair
- Prompts for a master password (minimum 12 characters)
- Encrypts the private key using Argon2id + ChaCha20-Poly1305
- Saves encrypted data to `.secure-ssh-data/`
- Creates a marker file for USB detection

### `secure-ssh pubkey`

Display your public SSH key in OpenSSH format.

```bash
./secure-ssh pubkey
```

**Output example:**
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx secure-ssh-key
```

### `secure-ssh server add`

Add a new server configuration.

```bash
./secure-ssh server add
```

**Prompts for:**
- Server name (alias)
- Host/IP address
- Port (default: 22)
- Username
- Description (optional)

### `secure-ssh server list`

Show all configured servers.

```bash
./secure-ssh server list
```

### `secure-ssh server remove <name>`

Remove a server configuration.

```bash
./secure-ssh server remove myserver
```

### `secure-ssh connect [name]`

Connect to a configured server.

```bash
# If only one server configured:
./secure-ssh connect

# Or specify server name:
./secure-ssh connect myserver
```

**Features:**
- Interactive terminal session
- Automatic terminal resize detection
- USB watchdog active (disconnects if USB removed)

### `secure-ssh change-pass`

Change the master password.

```bash
./secure-ssh change-pass
```

**What it does:**
- Prompts for current password
- Prompts for new password (with confirmation)
- Re-encrypts all data with new password

---

## How It Works

### File Structure

When initialized, secure-ssh creates the following in its directory:

```
/your-usb-drive/
├── secure-ssh              # The binary
├── .secure-ssh-data/       # Encrypted data directory
│   ├── key.enc             # Encrypted private key
│   ├── key.pub             # Public key (unencrypted)
│   └── servers.enc         # Encrypted server configs
└── .secure-ssh-marker      # USB detection marker
```

### Encryption Process

1. **Password → Key**: Argon2id derives a 256-bit key from your password
2. **Random salt**: Each encryption uses a unique random salt
3. **Random nonce**: ChaCha20-Poly1305 uses a unique nonce per encryption
4. **Authentication**: Poly1305 MAC ensures data integrity

### USB Watchdog

The watchdog monitors:
1. The marker file (`.secure-ssh-marker`)
2. Falls back to checking the executable's directory

When the USB drive is ejected:
- Active SSH sessions are terminated
- Private key is zeroed from memory
- Program exits gracefully

---

## Security Considerations

### Strengths

- **Memory-hard KDF**: Argon2id resists GPU/ASIC attacks
- **AEAD encryption**: ChaCha20-Poly1305 provides confidentiality + integrity
- **Ed25519**: Modern elliptic curve, resistant to timing attacks
- **Secure memory**: Keys zeroed on drop, prevented from swapping
- **No key caching**: Password required for each session

### Limitations

- **Physical access**: If someone has your USB and password, they have access
- **Screen capture**: Terminal output is visible on screen
- **Cold boot attacks**: Theoretically possible on frozen RAM
- **Malware**: If host system is compromised, keyloggers could capture password

### Best Practices

1. Use a strong master password (16+ characters recommended)
2. Keep your USB drive secure
3. Eject USB drive after use
4. Verify server fingerprints on first connection
5. Keep the binary up-to-date

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `argon2` | 0.5 | Password hashing |
| `chacha20poly1305` | 0.10 | Authenticated encryption |
| `ed25519-dalek` | 2.2 | SSH key generation |
| `russh` | 0.45 | SSH client implementation |
| `tokio` | 1.x | Async runtime |
| `zeroize` | 1.8 | Secure memory zeroing |
| `clap` | 4.x | CLI argument parsing |
| `crossterm` | 0.28 | Terminal handling |

Full list in `Cargo.toml`.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Run lints: `cargo clippy`
6. Submit a pull request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [RustCrypto](https://github.com/RustCrypto) for excellent cryptographic libraries
- [russh](https://github.com/warp-tech/russh) for the SSH implementation
- The Rust community for making secure software development accessible

---

## Author

Created with security in mind.

**Project Repository**: https://github.com/oracleh2/secure-ssh
