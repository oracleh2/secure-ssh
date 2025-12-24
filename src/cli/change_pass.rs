//! Смена мастер-пароля

use colored::Colorize;

use crate::config;
use crate::crypto::{self, KeyPair};
use crate::error::Result;

use super::{prompt_new_password, prompt_password};

pub fn run() -> Result<()> {
    if !config::is_initialized()? {
        return Err(crate::error::SecureSshError::NotInitialized);
    }

    println!("{}", "=== Смена мастер-пароля ===".cyan().bold());
    println!();

    // Получить текущий пароль
    println!("Введите текущий пароль:");
    let old_password = prompt_password()?;

    // Загрузить и расшифровать всё текущим паролем
    print!("{}", "Проверка текущего пароля... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let (private_key, old_salt) = config::load_encrypted_key(old_password.as_bytes())?;
    let servers = config::load_servers(old_password.as_bytes(), &old_salt)?;
    println!("{}", "готово".green());

    // Получить новый пароль
    println!();
    let new_password = prompt_new_password()?;
    println!();

    // Вычислить новый ключ шифрования
    print!("{}", "Вычисление нового ключа шифрования... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    let new_derived_key = crypto::derive_key(new_password.as_bytes(), None)?;
    println!("{}", "готово".green());

    // Восстановить keypair для получения публичного ключа
    let keypair = KeyPair::from_private_key(private_key)?;
    let public_key_openssh = keypair.public_key_openssh("secure-ssh-key");

    // Перешифровать всё новым паролем
    print!("{}", "Перешифровка данных... ".cyan());
    std::io::Write::flush(&mut std::io::stdout())?;

    config::save_encrypted_key(
        keypair.private_key_bytes(),
        &public_key_openssh,
        &new_derived_key,
    )?;

    config::save_servers(&servers, &new_derived_key)?;
    println!("{}", "готово".green());

    println!();
    println!("{}", "Пароль успешно изменён!".green().bold());

    Ok(())
}
