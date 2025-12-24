//! Обработка интерактивной SSH-сессии

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use tokio::sync::mpsc;
use crossterm::terminal::{self, enable_raw_mode, disable_raw_mode};
use russh::{client, Channel, ChannelMsg, Disconnect};

use crate::error::{Result, SecureSshError};
use crate::watchdog::UsbWatchdog;

/// Запустить интерактивную SSH-сессию с PTY
pub async fn run_interactive_session(
    session: client::Handle<super::SshClient>,
    mut channel: Channel<russh::client::Msg>,
    watchdog: Option<Box<dyn UsbWatchdog>>,
) -> Result<()> {
    // Запросить PTY
    let (cols, rows) = terminal::size().unwrap_or((80, 24));

    channel
        .request_pty(
            false,
            "xterm-256color",
            cols as u32,
            rows as u32,
            0,
            0,
            &[],
        )
        .await
        .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;

    // Запросить shell
    channel
        .request_shell(false)
        .await
        .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;

    // Флаг для завершения
    let shutdown = Arc::new(AtomicBool::new(false));

    // Текущий размер терминала для отслеживания изменений
    let current_cols = Arc::new(AtomicU16::new(cols));
    let current_rows = Arc::new(AtomicU16::new(rows));

    // Запустить USB watchdog если есть
    if let Some(wd) = watchdog {
        let shutdown_wd = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                if shutdown_wd.load(Ordering::Relaxed) {
                    break;
                }

                if !wd.is_present() {
                    eprintln!("\n\r[USB-накопитель извлечён - отключение...]");
                    shutdown_wd.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });
    }

    // Включить raw mode для корректной работы терминала
    enable_raw_mode().map_err(|e| SecureSshError::Other(e.to_string()))?;

    // Канал для stdin
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(100);

    // Канал для событий resize
    let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(10);

    // Поток чтения stdin
    let shutdown_stdin = shutdown.clone();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1024];

        loop {
            if shutdown_stdin.load(Ordering::Relaxed) {
                break;
            }

            match stdin.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Поток отслеживания resize
    let shutdown_resize = shutdown.clone();
    let cols_clone = current_cols.clone();
    let rows_clone = current_rows.clone();
    std::thread::spawn(move || {
        loop {
            if shutdown_resize.load(Ordering::Relaxed) {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(250));

            if let Ok((new_cols, new_rows)) = terminal::size() {
                let old_cols = cols_clone.load(Ordering::Relaxed);
                let old_rows = rows_clone.load(Ordering::Relaxed);

                if new_cols != old_cols || new_rows != old_rows {
                    cols_clone.store(new_cols, Ordering::Relaxed);
                    rows_clone.store(new_rows, Ordering::Relaxed);
                    let _ = resize_tx.blocking_send((new_cols, new_rows));
                }
            }
        }
    });

    // Основной цикл обработки событий
    let result = run_event_loop(&mut channel, &mut stdin_rx, &mut resize_rx, &shutdown).await;

    // Очистка
    shutdown.store(true, Ordering::Relaxed);
    disable_raw_mode().ok();

    // Корректно закрыть канал
    channel.eof().await.ok();
    channel.close().await.ok();

    // Отключиться от сессии
    session
        .disconnect(Disconnect::ByApplication, "User disconnected", "en")
        .await
        .ok();

    result
}

/// Основной цикл обработки stdin и данных канала
async fn run_event_loop(
    channel: &mut Channel<russh::client::Msg>,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    resize_rx: &mut mpsc::Receiver<(u16, u16)>,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    use std::io::Write;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Err(SecureSshError::UsbRemoved);
        }

        tokio::select! {
            // Сообщения от сервера
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        std::io::stdout().write_all(&data).ok();
                        std::io::stdout().flush().ok();
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: _ }) => {
                        std::io::stderr().write_all(&data).ok();
                        std::io::stderr().flush().ok();
                    }
                    Some(ChannelMsg::Eof) => {
                        // Сервер закрыл канал
                        break;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status: _ }) => {
                        // Shell завершился
                        break;
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        eprintln!("\r\n[Процесс завершён сигналом: {:?}]", signal_name);
                        break;
                    }
                    Some(ChannelMsg::Close) => {
                        break;
                    }
                    None => {
                        // Канал закрыт
                        break;
                    }
                    _ => {}
                }
            }

            // Ввод пользователя
            Some(data) = stdin_rx.recv() => {
                // Ctrl+D (EOF)
                if data.contains(&4) {
                    break;
                }

                channel.data(&data[..]).await
                    .map_err(|e| SecureSshError::SshConnectionFailed(e.to_string()))?;
            }

            // Изменение размера терминала
            Some((cols, rows)) = resize_rx.recv() => {
                channel.window_change(cols as u32, rows as u32, 0, 0).await.ok();
            }
        }
    }

    Ok(())
}
