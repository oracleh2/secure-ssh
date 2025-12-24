//! Отображение публичного SSH-ключа

use colored::Colorize;

use crate::config::read_public_key;
use crate::error::Result;

pub fn run() -> Result<()> {
    let public_key = read_public_key()?;

    println!();
    println!("{}", "Ваш публичный SSH-ключ:".cyan().bold());
    println!();
    println!("{}", "─".repeat(60).dimmed());
    println!("{}", public_key);
    println!("{}", "─".repeat(60).dimmed());
    println!();
    println!("Добавьте этот ключ в {} на ваших серверах.", "~/.ssh/authorized_keys".cyan());
    println!();

    Ok(())
}
