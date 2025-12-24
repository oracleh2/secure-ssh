use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process::ExitCode;

mod cli;
mod config;
mod crypto;
mod error;
mod ssh;
mod watchdog;

use error::Result;

#[derive(Parser)]
#[command(name = "secure-ssh")]
#[command(author = "Oleg")]
#[command(version = "0.1.0")]
#[command(about = "Безопасный SSH-клиент с защитой по типу аппаратного токена", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Инициализация с новым мастер-паролем и SSH-ключом
    Init,

    /// Показать публичный SSH-ключ
    Pubkey,

    /// Управление конфигурациями серверов
    Server {
        #[command(subcommand)]
        action: ServerCommands,
    },

    /// Подключиться к настроенному серверу
    Connect {
        /// Имя сервера (необязательно, если настроен только один)
        name: Option<String>,
    },

    /// Сменить мастер-пароль
    ChangePass,
}

#[derive(Subcommand)]
enum ServerCommands {
    /// Добавить новый сервер
    Add,
    /// Показать список серверов
    List,
    /// Удалить сервер
    Remove {
        /// Имя сервера для удаления
        name: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = run(cli);

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", "Ошибка:".red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init => cli::init::run(),
        Commands::Pubkey => cli::pubkey::run(),
        Commands::Server { action } => match action {
            ServerCommands::Add => cli::server::add(),
            ServerCommands::List => cli::server::list(),
            ServerCommands::Remove { name } => cli::server::remove(&name),
        },
        Commands::Connect { name } => cli::connect::run(name),
        Commands::ChangePass => cli::change_pass::run(),
    }
}
