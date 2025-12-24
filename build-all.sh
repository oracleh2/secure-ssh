#!/bin/bash
# Скрипт сборки для всех платформ

set -e

echo "=== Сборка secure-ssh для всех платформ ==="
echo

# Linux
echo "[1/4] Сборка для Linux x86_64..."
cargo build --release
echo "      Готово: target/release/secure-ssh"

# Windows
echo "[2/4] Сборка для Windows x86_64..."
cargo build --release --target x86_64-pc-windows-gnu
echo "      Готово: target/x86_64-pc-windows-gnu/release/secure-ssh.exe"

# macOS x86_64
echo "[3/4] Сборка для macOS x86_64..."
cargo zigbuild --release --target x86_64-apple-darwin
echo "      Готово: target/x86_64-apple-darwin/release/secure-ssh"

# macOS ARM64
echo "[4/4] Сборка для macOS ARM64 (Apple Silicon)..."
cargo zigbuild --release --target aarch64-apple-darwin
echo "      Готово: target/aarch64-apple-darwin/release/secure-ssh"

echo
echo "=== Сборка завершена ==="
echo
echo "Размеры бинарников:"
ls -lh target/release/secure-ssh \
       target/x86_64-pc-windows-gnu/release/secure-ssh.exe \
       target/x86_64-apple-darwin/release/secure-ssh \
       target/aarch64-apple-darwin/release/secure-ssh
