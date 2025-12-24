//! Подключение к настроенному серверу

use std::io::{self, Write};
use colored::Colorize;
use zeroize::Zeroize;

use crate::config::{self, Server};
use crate::error::{Result, SecureSshError};
use crate::ssh;
use crate::watchdog;

use super::prompt_password;

pub fn run(server_name: Option<String>) -> Result<()> {
    if !config::is_initialized()? {
        return Err(SecureSshError::NotInitialized);
    }

    // Получить пароль
    let mut password = prompt_password()?;

    // Загрузить зашифрованный ключ
    print!("{}", "Расшифровка SSH-ключа... ".cyan());
    io::stdout().flush()?;

    let (private_key, salt) = match config::load_encrypted_key(password.as_bytes()) {
        Ok(result) => result,
        Err(e) => {
            password.zeroize();
            println!("{}", "ошибка".red());
            return Err(e);
        }
    };
    println!("{}", "готово".green());

    // Загрузить серверы
    let servers = config::load_servers(password.as_bytes(), &salt)?;

    // Очистить пароль из памяти
    password.zeroize();

    if servers.is_empty() {
        return Err(SecureSshError::NoServersConfigured);
    }

    // Выбрать сервер
    let server = select_server(&servers, server_name)?;

    println!();
    println!(
        "{} {}",
        "Подключение к:".cyan(),
        server.connection_string().bold()
    );

    // Создать watchdog
    let watchdog = watchdog::create_watchdog();
    if watchdog.is_some() {
        println!("{}", "USB watchdog активен - извлечение накопителя прервёт соединение".dimmed());
    }

    println!();

    // Запустить асинхронное SSH-подключение
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| SecureSshError::Other(format!("Не удалось создать async runtime: {}", e)))?;

    let result = runtime.block_on(async {
        connect_and_run(&server, &private_key, watchdog).await
    });

    // Очистить приватный ключ из памяти
    drop(private_key);

    match result {
        Ok(()) => {
            println!();
            println!("{}", "Отключено.".green());
            Ok(())
        }
        Err(SecureSshError::UsbRemoved) => {
            println!();
            println!("{}", "USB-накопитель извлечён - соединение прервано.".yellow());
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Выбрать сервер из списка
fn select_server(servers: &config::ServerList, name: Option<String>) -> Result<&Server> {
    match name {
        Some(n) => servers
            .get(&n)
            .ok_or_else(|| SecureSshError::ServerNotFound(n)),
        None => {
            if servers.len() == 1 {
                // Только один сервер - используем его
                Ok(servers.first().unwrap())
            } else {
                // Несколько серверов - попросить выбрать
                println!("{}", "Доступные серверы:".cyan().bold());
                println!();

                for (i, server) in servers.iter().enumerate() {
                    println!(
                        "  {} {} - {}",
                        format!("[{}]", i + 1).cyan(),
                        server.name.bold(),
                        server.connection_string()
                    );
                }

                println!();
                print!("Выберите сервер [1-{}]: ", servers.len());
                io::stdout().flush()?;

                let mut input = String::new();
                io::stdin().read_line(&mut input)?;

                let choice: usize = input
                    .trim()
                    .parse()
                    .map_err(|_| SecureSshError::InvalidConfig("Неверный выбор".into()))?;

                if choice < 1 || choice > servers.len() {
                    return Err(SecureSshError::InvalidConfig("Неверный выбор".into()));
                }

                servers
                    .iter()
                    .nth(choice - 1)
                    .ok_or_else(|| SecureSshError::InvalidConfig("Неверный выбор".into()))
            }
        }
    }
}

/// Подключиться к серверу и запустить интерактивную сессию
async fn connect_and_run(
    server: &Server,
    private_key: &[u8],
    watchdog: Option<Box<dyn watchdog::UsbWatchdog>>,
) -> Result<()> {
    // Подключиться
    let (session, channel) = ssh::connect(
        &server.host,
        server.port,
        &server.user,
        private_key,
    )
    .await?;

    // Запустить интерактивную сессию
    ssh::run_interactive_session(session, channel, watchdog).await
}
