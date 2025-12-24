//! Инициализация secure-ssh с новым мастер-паролем и SSH-ключом

use colored::Colorize;

use crate::config::{self, Server, ServerList};
use crate::crypto::{self, KeyPair};
use crate::error::{Result, SecureSshError};

use super::{confirm, prompt_new_password};

pub fn run() -> Result<()> {
    println!("{}", "=== Инициализация Secure SSH ===".cyan().bold());
    println!();

    // Проверить, инициализировано ли уже
    if config::is_initialized()? {
        println!(
            "{} secure-ssh уже инициализирован.",
            "Внимание:".yellow().bold()
        );
        println!("Реинициализация создаст новый SSH-ключ.");
        println!("Вам нужно будет обновить authorized_keys на всех серверах.\n");

        if !confirm("Выполнить реинициализацию?") {
            println!("Отменено.");
            return Ok(());
        }
        println!();
    }

    // Получить мастер-пароль
    let password = prompt_new_password()?;
    println!();

    // Получить ключ шифрования
    print!("{}", "Вычисление ключа шифрования (это займёт некоторое время)... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let derived_key = crypto::derive_key(password.as_bytes(), None)?;
    println!("{}", "готово".green());

    // Сгенерировать SSH-ключи
    print!("{}", "Генерация SSH-ключа Ed25519... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let keypair = KeyPair::generate()?;
    println!("{}", "готово".green());

    // Получить публичный ключ в формате OpenSSH
    let public_key_openssh = keypair.public_key_openssh("secure-ssh-key");

    // Сохранить зашифрованный ключ
    print!("{}", "Сохранение зашифрованного ключа... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    config::save_encrypted_key(
        keypair.private_key_bytes(),
        &public_key_openssh,
        &derived_key,
    )?;
    println!("{}", "готово".green());

    // Создать файл-маркер для watchdog
    print!("{}", "Создание файла-маркера... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    config::create_marker_file()?;
    println!("{}", "готово".green());

    // Спросить о настройке сервера
    println!();
    println!("{}", "=== Настройка сервера ===".cyan().bold());
    println!();

    if confirm("Добавить сервер сейчас?") {
        let server = prompt_server_config()?;
        let mut servers = ServerList::new();
        servers.add(server).map_err(|e| SecureSshError::Other(e.to_string()))?;
        config::save_servers(&servers, &derived_key)?;
        println!("{}", "Сервер добавлен!".green());
    }

    // Показать результат и публичный ключ
    println!();
    println!("{}", "=== Инициализация завершена ===".green().bold());
    println!();
    println!("Ваш публичный SSH-ключ (добавьте на серверы):");
    println!();
    println!("{}", "─".repeat(60).dimmed());
    println!("{}", public_key_openssh);
    println!("{}", "─".repeat(60).dimmed());
    println!();
    println!("Для добавления ключа на сервер выполните:");
    println!(
        "  {} user@host 'mkdir -p ~/.ssh && echo \"{}\" >> ~/.ssh/authorized_keys'",
        "ssh".cyan(),
        public_key_openssh
    );
    println!();
    println!("Или скопируйте публичный ключ из файла:");
    println!("  {}", config::get_public_key_path()?.display().to_string().cyan());
    println!();
    println!(
        "Для подключения к серверу выполните: {}",
        "secure-ssh connect".cyan()
    );

    Ok(())
}

/// Запросить данные конфигурации сервера
fn prompt_server_config() -> Result<Server> {
    use std::io::{self, Write};

    println!();

    // Имя сервера
    print!("Имя сервера [main]: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();
    let name = if name.is_empty() { "main" } else { name };

    // Хост
    print!("Хост/IP [185.93.107.57]: ");
    io::stdout().flush()?;
    let mut host = String::new();
    io::stdin().read_line(&mut host)?;
    let host = host.trim();
    let host = if host.is_empty() { "185.93.107.57" } else { host };

    // Порт
    print!("Порт [22]: ");
    io::stdout().flush()?;
    let mut port_str = String::new();
    io::stdin().read_line(&mut port_str)?;
    let port_str = port_str.trim();
    let port: u16 = if port_str.is_empty() {
        22
    } else {
        port_str.parse().unwrap_or(22)
    };

    // Пользователь
    print!("Имя пользователя [oleg]: ");
    io::stdout().flush()?;
    let mut user = String::new();
    io::stdin().read_line(&mut user)?;
    let user = user.trim();
    let user = if user.is_empty() { "oleg" } else { user };

    // Описание
    print!("Описание (опционально): ");
    io::stdout().flush()?;
    let mut description = String::new();
    io::stdin().read_line(&mut description)?;
    let description = description.trim();

    let mut server = Server::new(name, host, port, user);
    if !description.is_empty() {
        server = server.with_description(description);
    }

    Ok(server)
}
