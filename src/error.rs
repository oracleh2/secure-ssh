use thiserror::Error;

pub type Result<T> = std::result::Result<T, SecureSshError>;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum SecureSshError {
    #[error("Не инициализировано. Сначала выполните 'secure-ssh init'.")]
    NotInitialized,

    #[error("Уже инициализировано. Используйте --force для повторной инициализации (это удалит существующие ключи).")]
    AlreadyInitialized,

    #[error("Неверный пароль")]
    InvalidPassword,

    #[error("Пароль слишком короткий (минимум 12 символов)")]
    PasswordTooShort,

    #[error("Пароли не совпадают")]
    PasswordMismatch,

    #[error("Ошибка расшифровки: данные повреждены или пароль неверный")]
    DecryptionFailed,

    #[error("Ошибка шифрования: {0}")]
    EncryptionFailed(String),

    #[error("Сервер '{0}' не найден")]
    ServerNotFound(String),

    #[error("Сервер '{0}' уже существует")]
    ServerAlreadyExists(String),

    #[error("Серверы не настроены. Сначала выполните 'secure-ssh server add'.")]
    NoServersConfigured,

    #[error("Ошибка SSH-подключения: {0}")]
    SshConnectionFailed(String),

    #[error("Ошибка SSH-аутентификации")]
    SshAuthFailed,

    #[error("USB-накопитель извлечён - соединение прервано")]
    UsbRemoved,

    #[error("Операция отменена пользователем")]
    Cancelled,

    #[error("Неверная конфигурация: {0}")]
    InvalidConfig(String),

    #[error("Ошибка генерации ключа: {0}")]
    KeyGenerationFailed(String),

    #[error("Ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),

    #[error("Ошибка JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}
