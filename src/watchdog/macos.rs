//! Watchdog для macOS - отслеживание USB-накопителя

use std::path::PathBuf;
use super::UsbWatchdog;
use crate::config;

/// Реализация watchdog для macOS
pub struct MacOsWatchdog {
    /// Путь для мониторинга (обычно /Volumes/XXX)
    watch_path: PathBuf,
    /// Файл-маркер для проверки
    marker_file: Option<PathBuf>,
}

impl MacOsWatchdog {
    pub fn new() -> Option<Self> {
        let exe_dir = config::get_exe_dir().ok()?;

        // Ищем маркер-файл
        let marker = config::get_marker_path().ok();
        let marker_exists = marker.as_ref().map(|p| p.exists()).unwrap_or(false);

        Some(Self {
            watch_path: exe_dir,
            marker_file: if marker_exists { marker } else { None },
        })
    }

    /// Проверить, запущено ли из /Volumes (съёмные носители на macOS)
    #[allow(dead_code)]
    pub fn is_removable(&self) -> bool {
        let path_str = self.watch_path.to_string_lossy();
        path_str.starts_with("/Volumes/")
    }
}

impl UsbWatchdog for MacOsWatchdog {
    fn is_present(&self) -> bool {
        // Сначала проверяем маркер-файл
        if let Some(ref marker) = self.marker_file {
            return marker.exists();
        }

        // Иначе проверяем директорию
        self.watch_path.exists()
    }
}
