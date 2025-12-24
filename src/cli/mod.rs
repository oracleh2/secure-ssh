//! Реализация CLI команд

pub mod change_pass;
pub mod connect;
pub mod init;
pub mod pubkey;
pub mod server;

use std::io::{self, Write};
use colored::Colorize;

/// Минимальная длина пароля
pub const MIN_PASSWORD_LEN: usize = 12;

/// Запросить новый пароль с подтверждением
pub fn prompt_new_password() -> crate::error::Result<String> {
    println!("{}", "Создание мастер-пароля".cyan().bold());
    println!("Этот пароль шифрует ваш SSH-ключ. Выберите надёжный пароль.");
    println!("Минимальная длина: {} символов\n", MIN_PASSWORD_LEN);

    loop {
        let password = rpassword::prompt_password("Введите мастер-пароль: ")?;

        if password.len() < MIN_PASSWORD_LEN {
            println!(
                "{} Пароль должен содержать минимум {} символов",
                "Ошибка:".red(),
                MIN_PASSWORD_LEN
            );
            continue;
        }

        let confirm = rpassword::prompt_password("Подтвердите мастер-пароль: ")?;

        if password != confirm {
            println!("{} Пароли не совпадают", "Ошибка:".red());
            continue;
        }

        return Ok(password);
    }
}

/// Запросить существующий пароль
pub fn prompt_password() -> crate::error::Result<String> {
    let password = rpassword::prompt_password("Введите мастер-пароль: ")?;
    Ok(password)
}

/// Запросить подтверждение да/нет
pub fn confirm(prompt: &str) -> bool {
    print!("{} [y/N] ", prompt);
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    matches!(input.trim().to_lowercase().as_str(), "y" | "yes" | "д" | "да")
}
