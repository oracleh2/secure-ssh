//! Watchdog для Linux - отслеживание USB-накопителя

use std::path::PathBuf;
use super::UsbWatchdog;
use crate::config;

/// Реализация watchdog для Linux
pub struct LinuxWatchdog {
    /// Путь для мониторинга (директория exe или маркер-файл)
    watch_path: PathBuf,
    /// Файл-маркер для проверки
    marker_file: Option<PathBuf>,
}

impl LinuxWatchdog {
    pub fn new() -> Option<Self> {
        let exe_dir = config::get_exe_dir().ok()?;

        // Ищем файл-маркер
        let marker = config::get_marker_path().ok();
        let marker_exists = marker.as_ref().map(|p| p.exists()).unwrap_or(false);

        Some(Self {
            watch_path: exe_dir,
            marker_file: if marker_exists { marker } else { None },
        })
    }

    /// Проверить, запущено ли со съёмного устройства
    #[allow(dead_code)]
    pub fn is_removable(&self) -> bool {
        let path_str = self.watch_path.to_string_lossy();

        // Типичные точки монтирования съёмных устройств в Linux
        path_str.starts_with("/media/")
            || path_str.starts_with("/mnt/")
            || path_str.starts_with("/run/media/")
    }
}

impl UsbWatchdog for LinuxWatchdog {
    fn is_present(&self) -> bool {
        // Сначала проверяем маркер-файл (более надёжно)
        if let Some(ref marker) = self.marker_file {
            return marker.exists();
        }

        // Иначе проверяем директорию
        self.watch_path.exists()
    }
}
