//! Команды управления серверами

use std::io::{self, Write};
use colored::Colorize;

use crate::config::{self, Server};
use crate::crypto;
use crate::error::{Result, SecureSshError};

use super::prompt_password;

/// Добавить новый сервер
pub fn add() -> Result<()> {
    if !config::is_initialized()? {
        return Err(SecureSshError::NotInitialized);
    }

    println!("{}", "=== Добавление сервера ===".cyan().bold());
    println!();

    // Получить пароль для расшифровки конфига
    let password = prompt_password()?;

    // Загрузить существующий ключ для получения соли
    let (_, salt) = config::load_encrypted_key(password.as_bytes())?;

    // Загрузить существующие серверы
    let mut servers = config::load_servers(password.as_bytes(), &salt)?;

    // Запросить данные нового сервера
    let server = prompt_server_details()?;

    // Проверить, не существует ли уже
    if servers.get(&server.name).is_some() {
        return Err(SecureSshError::ServerAlreadyExists(server.name));
    }

    // Добавить и сохранить
    servers.add(server.clone()).map_err(|e| SecureSshError::Other(e.to_string()))?;

    let derived_key = crypto::derive_key(password.as_bytes(), Some(&salt))?;
    config::save_servers(&servers, &derived_key)?;

    println!();
    println!(
        "{} Сервер '{}' добавлен!",
        "Успех:".green().bold(),
        server.name
    );

    Ok(())
}

/// Показать список всех настроенных серверов
pub fn list() -> Result<()> {
    if !config::is_initialized()? {
        return Err(SecureSshError::NotInitialized);
    }

    println!("{}", "=== Настроенные серверы ===".cyan().bold());
    println!();

    let password = prompt_password()?;

    // Загрузить существующий ключ для получения соли
    let (_, salt) = config::load_encrypted_key(password.as_bytes())?;

    // Загрузить серверы
    let servers = config::load_servers(password.as_bytes(), &salt)?;

    if servers.is_empty() {
        println!("Серверы не настроены.");
        println!();
        println!(
            "Выполните {} для добавления сервера.",
            "secure-ssh server add".cyan()
        );
        return Ok(());
    }

    println!(
        "{:<15} {:<30} {:<20}",
        "ИМЯ".bold(),
        "ПОДКЛЮЧЕНИЕ".bold(),
        "ОПИСАНИЕ".bold()
    );
    println!("{}", "─".repeat(65).dimmed());

    for server in servers.iter() {
        println!(
            "{:<15} {:<30} {:<20}",
            server.name,
            server.connection_string(),
            server.description
        );
    }

    println!();
    Ok(())
}

/// Удалить сервер
pub fn remove(name: &str) -> Result<()> {
    if !config::is_initialized()? {
        return Err(SecureSshError::NotInitialized);
    }

    println!("{}", "=== Удаление сервера ===".cyan().bold());
    println!();

    let password = prompt_password()?;

    // Загрузить существующий ключ для получения соли
    let (_, salt) = config::load_encrypted_key(password.as_bytes())?;

    // Загрузить серверы
    let mut servers = config::load_servers(password.as_bytes(), &salt)?;

    // Удалить сервер
    if servers.remove(name).is_none() {
        return Err(SecureSshError::ServerNotFound(name.to_string()));
    }

    // Сохранить обновлённый список
    let derived_key = crypto::derive_key(password.as_bytes(), Some(&salt))?;
    config::save_servers(&servers, &derived_key)?;

    println!(
        "{} Сервер '{}' удалён.",
        "Успех:".green().bold(),
        name
    );

    Ok(())
}

/// Запросить данные сервера
fn prompt_server_details() -> Result<Server> {
    // Имя сервера
    print!("Имя сервера: ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim().to_string();

    if name.is_empty() {
        return Err(SecureSshError::InvalidConfig("Имя сервера не может быть пустым".into()));
    }

    // Хост
    print!("Хост/IP: ");
    io::stdout().flush()?;
    let mut host = String::new();
    io::stdin().read_line(&mut host)?;
    let host = host.trim().to_string();

    if host.is_empty() {
        return Err(SecureSshError::InvalidConfig("Хост не может быть пустым".into()));
    }

    // Порт
    print!("Порт [22]: ");
    io::stdout().flush()?;
    let mut port_str = String::new();
    io::stdin().read_line(&mut port_str)?;
    let port_str = port_str.trim();
    let port: u16 = if port_str.is_empty() {
        22
    } else {
        port_str
            .parse()
            .map_err(|_| SecureSshError::InvalidConfig("Неверный номер порта".into()))?
    };

    // Пользователь
    print!("Имя пользователя: ");
    io::stdout().flush()?;
    let mut user = String::new();
    io::stdin().read_line(&mut user)?;
    let user = user.trim().to_string();

    if user.is_empty() {
        return Err(SecureSshError::InvalidConfig("Имя пользователя не может быть пустым".into()));
    }

    // Описание
    print!("Описание (опционально): ");
    io::stdout().flush()?;
    let mut description = String::new();
    io::stdin().read_line(&mut description)?;
    let description = description.trim().to_string();

    let mut server = Server::new(name, host, port, user);
    if !description.is_empty() {
        server = server.with_description(description);
    }

    Ok(server)
}
